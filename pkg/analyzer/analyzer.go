package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type ProcessBehavior struct {
	PID       uint32    `json:"pid"`
	StartTime time.Time `json:"start_time"`
	LastSeen  time.Time `json:"last_seen"`
	Filenames []string  `json:"filenames"`
}

type RiskReport struct {
	PID        uint32   `json:"pid"`
	RiskLevel  string   `json:"risk_level"`
	Reasons    []string `json:"reasons"`
	Suggestion string   `json:"suggestion"`
}

type Analyzer interface {
	Analyze(behavior *ProcessBehavior) (*RiskReport, error)
}

type MinimaxConfig struct {
	APIKey     string
	APIBaseURL string
	Model      string
}

type MinimaxAnalyzer struct {
	client *http.Client
	config MinimaxConfig
}

func NewMinimaxAnalyzer(apiKey string) *MinimaxAnalyzer {
	return &MinimaxAnalyzer{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		config: MinimaxConfig{
			APIKey:     apiKey,
			APIBaseURL: "https://api.minimax.chat/v1",
			Model:      "Minimax-2.7",
		},
	}
}

func BuildPrompt(behavior *ProcessBehavior) string {
	var buf bytes.Buffer
	buf.WriteString("你是一个进程行为安全分析专家。请分析以下进程行为是否具有恶意意图。\n\n")
	buf.WriteString("进程信息：\n")
	buf.WriteString(fmt.Sprintf("- 进程 PID: %d\n", behavior.PID))
	buf.WriteString(fmt.Sprintf("- 首次出现时间: %s\n", behavior.StartTime.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("- 最后活跃时间: %s\n", behavior.LastSeen.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("- 时间窗口内执行文件数: %d\n\n", len(behavior.Filenames)))

	buf.WriteString("执行的文件路径列表：\n")
	seen := make(map[string]bool)
	for i, path := range behavior.Filenames {
		if !seen[path] {
			buf.WriteString(fmt.Sprintf("  %d. %s\n", i+1, path))
			seen[path] = true
		}
	}
	buf.WriteString("\n请以JSON格式返回分析结果，字段包括：\n")
	buf.WriteString("- risk_level: 风险等级（low/medium/high/critical）\n")
	buf.WriteString("- reasons: 判断理由（字符串数组）\n")
	buf.WriteString("- suggestion: 处置建议\n")

	return buf.String()
}

func (a *MinimaxAnalyzer) Analyze(behavior *ProcessBehavior) (*RiskReport, error) {
	prompt := BuildPrompt(behavior)

	reqBody := map[string]interface{}{
		"model": a.config.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"response_format": map[string]string{"type": "json_object"},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", a.config.APIBaseURL+"/text/chatcompletion_v2", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.config.APIKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call LLM API: %w", err)
	}
	defer resp.Body.Close()

	var llmResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return nil, fmt.Errorf("failed to decode LLM response: %w", err)
	}

	if len(llmResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from LLM")
	}

	var report RiskReport
	if err := json.Unmarshal([]byte(llmResp.Choices[0].Message.Content), &report); err != nil {
		return nil, fmt.Errorf("failed to parse risk report: %w", err)
	}

	report.PID = behavior.PID
	return &report, nil
}
