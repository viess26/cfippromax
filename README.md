# cfip

自动收集 **Cloudflare 优选 IP** 和 **家宽 IP**，GitHub Actions 定时更新。

- `results/cfip.txt`：`IP:443#机房-延迟`
- `results/residential_proxy.txt`：家宽 **反代 IP**（能反代 Cloudflare），`IP:端口#国家-运营商-机房-延迟`
- `results/residential_direct.txt`：家宽 **非反代 IP**，`IP:端口#国家-运营商-延迟`
- `results/openvpn.txt`：家宽 OpenVPN 节点列表 `IP:端口/协议#国家-运营商-延迟-速度`
- `results/ovpn/*.ovpn`：对应的可直接导入客户端的配置文件

## 使用
1. Fork / 新建仓库，上传本项目文件
2. 编辑 `config.json`，在 `residential.sources` 填入你的家宽 IP 列表源（URL，纯文本，每行 `ip` 或 `ip:port`）
3. Actions → update → Run workflow
4. 订阅地址：`https://raw.githubusercontent.com/<你>/<仓库>/main/results/cfip.txt`

## 说明
- CF 部分：取官方 IP 段随机采样 → TCP 延迟 → 取前 N → 读取 colo。
  注意这是**本机(Actions 机房)视角**的延迟，与你本地网络最优 IP 不同，想要贴合自己线路请在本地运行。
- 反代判定：用 CF 域名 SNI 访问该 IP 的 443，若 `/cdn-cgi/trace` 返回 `colo=`，即为反代 IP，否则归入非反代。
- 家宽判定：ip-api 的 `hosting=false` 且非移动网络。准确度有限，仅供参考。

- OpenVPN 节点来自 [VPN Gate](https://www.vpngate.net)（志愿者 PC，不少是家宽），按 VPN Gate 评分排序，再用 ip-api 剔除机房/移动 IP。节点上下线频繁，建议定时更新；第三方节点可能记录日志，不要用来传输敏感数据。

## 家宽 IP 来源汇总
1. `sources`：在线 IP 列表（txt/CSV）
2. `my_sources.txt`：自己收集的 IP
3. `domains`：域名解析（DDNS 域名、公开 ProxyIP 域名），可写 `域名:端口`
4. Shodan / FOFA：在仓库 Settings → Secrets 设置 `SHODAN_KEY` 或 `FOFA_EMAIL`+`FOFA_KEY`，再在 `config.json` 填查询语句；没配 key 会自动跳过
5. VPN Gate：OpenVPN 志愿者节点（单独输出）
