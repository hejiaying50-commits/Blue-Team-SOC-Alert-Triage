# GitHub 展示上传指南

这份文档用于帮助你把当前项目上传到 GitHub 后，进一步把仓库展示效果做完整。

## 1. 仓库名称建议

- `Blue-Team-SOC-Alert-Triage`
- `blue-team-soc-alert-triage`

## 2. 仓库简介（GitHub About）

推荐直接填写：

> A local blue-team SOC alert triage and web attack incident response project built with Python, pandas, Streamlit, and Suricata-style logs.

如果想用中文：

> 基于 Python 的蓝队 SOC 告警研判与 Web 攻击日志应急响应平台，支持多源日志解析、规则检测、风险评分、事件聚合与安全态势展示。

## 3. Topics 标签建议

建议添加这些 GitHub topics：

- `blue-team`
- `soc`
- `cybersecurity`
- `security-operations`
- `incident-response`
- `log-analysis`
- `streamlit`
- `python`
- `suricata`
- `pandas`

## 4. 建议保留在仓库中的展示材料

建议保留：

- `README.md`
- `LICENSE`
- `requirements.txt`
- `run_pipeline.py`
- `rules/detection_rules.yaml`
- `dashboard/app.py`
- `reports/daily_security_report.xlsx`
- `reports/incident_report.md`
- `screenshots/dashboard_overview.png`
- `screenshots/high_risk_incidents.png`

## 5. 建议上传前检查

- 确认 `README.md` 首页图片可正常显示。
- 确认 `python run_pipeline.py` 可在新环境复现输出。
- 确认 `streamlit run dashboard/app.py` 可正常启动。
- 确认 `screenshots/` 下截图存在。
- 确认没有上传虚拟环境、`__pycache__` 或本地 IDE 临时文件。

## 6. Git 命令参考

```bash
git init
git add .
git commit -m "feat: initial blue-team SOC alert triage project"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

## 7. 建议在 GitHub 页面额外设置

- 将本仓库 pin 到个人主页。
- 在仓库右侧 About 区域填写简介和网址。
- 补上 topics 标签。
- 上传后在 README 首屏确认截图显示是否正常。
- 如果你后面做了 v2，可以发一个 `v1.0` Release。
