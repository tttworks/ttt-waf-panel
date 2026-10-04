# 需自行下载的数据文件

> **为什么单独写这一份？** 有两类数据因**许可限制**不能随本项目分发（详见 `THIRD-PARTY-NOTICES.md`）。
> 请按下面步骤自行获取。
>
> **不下载也完全可以用** —— 面板会正常运行，只是**世界地图为空**、**国家/城市统计显示「未知」**。

---

## 1. GeoLite2-City.mmdb（IP 地理位置库，约 65MB）

**用途**：把访问日志里的来源 IP 解析成国家 / 城市 / 经纬度，用于「世界地图」与「国家 Top20」统计。

**放置位置**：面板根目录，即与 `api.php` 同级 → `/www/wwwroot/wafpanel/GeoLite2-City.mmdb`

### 获取步骤

1. 注册 MaxMind 账号（免费）：https://www.maxmind.com/en/geolite2/signup
2. 登录后进入 **Download Databases** 页面
3. 选择 **GeoLite2 City** → 格式选 **MaxMind DB (.mmdb)** → 下载 **GZIP** 包
4. 解压后得到 `GeoLite2-City.mmdb`，上传到面板目录：

```bash
# 本地解压后上传（示例）
gunzip GeoLite2-City-CSV_*.zip 2>/dev/null; tar -xzf GeoLite2-City_*.tar.gz
scp GeoLite2-City_*/GeoLite2-City.mmdb root@<服务器IP>:/www/wwwroot/wafpanel/

# 服务器上修正属主（宝塔机为 www，Ubuntu 系为 www-data）
chown www:www /www/wwwroot/wafpanel/GeoLite2-City.mmdb
chmod 644 /www/wwwroot/wafpanel/GeoLite2-City.mmdb
```

5. 验证：

```bash
ls -la /www/wwwroot/wafpanel/GeoLite2-City.mmdb   # 应有约 65MB
```

> **许可提示**：GeoLite2 受 MaxMind EULA 约束，**不得再分发**。请勿把它提交到任何公开仓库。
> **更新**：MaxMind 每月更新数据库；建议每季度手动替换一次（或写脚本自动下载，但注意其条款对自动化的限制）。

---

## 2. 地图轮廓数据（阿里 DataV GeoAtlas）

**用途**：ECharts 渲染中国地图与世界地图的国界/省界轮廓。

**放置位置**：`lib/` 目录下两个文件

| 文件名 | 内容 | 大致大小 |
|---|---|---|
| `lib/china.json` | 中国地图（含省份轮廓） | 约 580KB |
| `lib/world_cn.json` | 世界地图（国界轮廓，中文名） | 约 1.6MB |

### 获取步骤

阿里 DataV GeoAtlas 提供公开的边界数据接口：

```bash
cd /www/wwwroot/wafpanel/lib/

# 中国地图（含省级）
curl -sL -o china.json \
  "https://geo.datav.aliyun.com/areas_v3/bound/100000_full.json"

# 世界地图（各国轮廓）
curl -sL -o world_cn.json \
  "https://geo.datav.aliyun.com/areas_v3/bound/world.json"
```

> ⚠️ **请在使用前自行确认数据来源的使用条款**。如果你的使用场景对地图数据许可有严格要求（尤其商用分发），建议改用许可明确的数据源，例如：
> - **Natural Earth**（公有领域）：https://www.naturalearthdata.com/
> - **ECharts 官方地图数据**：https://github.com/apache/echarts（注意其地图数据部分有单独说明）
>
> 转换后只要**保持文件名与 GeoJSON 结构不变**（顶层为 `{"type":"FeatureCollection","features":[...]}`），面板即可直接使用。

### 验证

```bash
ls -la lib/china.json lib/world_cn.json
head -c 80 lib/china.json      # 应看到 {"type":"FeatureCollection"...
```

---

## 3. 检查清单

装完数据后，打开面板确认：

- [ ] 「概览」页的**世界地图**有国家轮廓与点位
- [ ] 「概览」页**国家 Top20** 有国家名称（而不是全部「未知」）
- [ ] 「地图」页可切换 浅色 / 深色 / 卫星 三种底图

若地图空白但其它功能正常 → 就是这两个数据文件没放对位置。
