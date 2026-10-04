# 第三方组件与许可声明

本项目采用 **Apache License 2.0**（见 `LICENSE`）。以下第三方组件的权利归其各自所有者，使用与再分发分别受其许可约束。

---

## 1. 已随仓库分发的组件

### Apache ECharts

- **文件**：`lib/echarts.min.js`
- **用途**：面板图表（趋势、国家统计、环形图等）
- **许可**：Apache License 2.0
- **版权**：Copyright © Apache Software Foundation
- **说明**：可自由再分发。本仓库保留其原始文件，未作修改。

---

## 2. 需使用者自行下载的组件（因许可限制，本项目**不**随仓库分发）

### GeoLite2 City 数据库

- **文件**：`GeoLite2-City.mmdb`
- **用途**：将来源 IP 解析为国家 / 城市 / 经纬度，用于世界地图与地区统计
- **来源**：https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- **许可**：MaxMind GeoLite2 End User License Agreement + CC BY-SA 4.0
- **⚠️ 为什么不随仓库分发**：MaxMind 的 EULA 明确限制再分发，且需注册账号获取
- **获取方式**：见 `DATA.md`

### 地图轮廓数据

- **文件**：`lib/china.json`、`lib/world_cn.json`
- **用途**：ECharts 地图渲染的国家 / 省份轮廓
- **来源**：阿里 DataV GeoAtlas（`https://geo.datav.aliyun.com/areas_v3/bound/`）
- **许可**：见来源站点条款（**未明确授予再分发**，故本项目不打包）
- **获取方式**：见 `DATA.md`

> **不下载这些会怎样？** 面板仍可正常运行 —— 只是世界地图为空、国家/城市统计显示「未知」。其余功能（拦截明细、站点、规则管理、安全检测）完全不受影响。

---

## 3. 运行时依赖（由使用者环境提供）

| 组件 | 用途 | 许可 |
|---|---|---|
| nginx | 反向代理 + WAF 规则层（`map` 指令） | BSD-2-Clause |
| PHP 8.x（`pdo_sqlite` / `mbstring` / `curl`） | 面板后端 | PHP License 3.01 |
| Python 3.8+（`geoip2`） | 日志采集与 GeoIP 富化 | PSF License |
| SQLite | 数据存储 | Public Domain |
| fail2ban | 登录爆破封禁（可选） | GPL-2.0 |

---

*本文件仅作声明用途；如与各组件的官方许可文本有出入，以官方文本为准。*
