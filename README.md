# cfip

自动收集 **Cloudflare 优选 IP**，GitHub Actions 每 6 小时更新一次。

- `results/cfip.txt`：`IP:443#机房-延迟`

## 来源
官方 IPv4 段、`config.json` 里的 `extra_sources` 在线列表（支持 IP/CIDR）、`my_cf.txt` 本地文件。合并后统一测延迟，取最快的 `top_n` 个。

## 使用
1. 上传本项目文件，并创建 `.github/workflows/update.yml`
2. Settings → Actions → General → Workflow permissions 选 Read and write
3. Actions → update → Run workflow
4. 订阅地址：`https://raw.githubusercontent.com/<你>/<仓库>/main/results/cfip.txt`

## 本地验证
Actions 测的是美国机房视角，国内用请在自己电脑上复测（先下载结果文件到本地，关闭代理）：

    python verify.py cfip.txt --tcp     # 只测端口连通和延迟
    python verify.py cfip.txt           # 额外检查 /cdn-cgi/trace

结果输出到 `results/` 文件夹。

## 按地区保留
- `results/cfip_all.txt` 是候选池（最多 `pool_n`(默认 3000) 个存活 IP）。
- 机房(地区)取决于**测试者所在位置**，Actions 在美国，测出来基本都是美国机房。想按地区挑，要在自己电脑上运行：

      python verify.py cfip_all.txt --total=100

  总共保留 100 个，各机房轮流各取最快的一个，直到凑够，保证每个地区都有。
  可选：`--per-colo=5` 限制每个机房最多 5 个；`--by=loc` 改成按国家分组。结果在 `results/proxy_verified.txt`。
