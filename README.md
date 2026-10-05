# Shadowrocket 国内核心广告订阅

目标仓库：`juscice/shadowrocket-subscription`，默认分支 `main`。

此目录是可直接上传的完整仓库内容。上传完成之前，以下 GitHub 链接不会生效。

## 订阅链接

完整配置：

```
https://raw.githubusercontent.com/juscice/shadowrocket-subscription/main/dist/shadowrocket.conf
```

去广告模块：

```
https://raw.githubusercontent.com/juscice/shadowrocket-subscription/main/dist/adblock.sgmodule
```

功能增强模块：

```
https://raw.githubusercontent.com/juscice/shadowrocket-subscription/main/dist/enhance.sgmodule
```

完整配置已经包含去广告和增强，使用完整配置时不要再叠加两个模块。文件不提供代理节点订阅；继续使用自己的节点。微信读书脚本保持 `enable=true`，仅上游声明的旧版兼容范围，效果未作手机实测。

在 Shadowrocket 的“配置”中从 URL 添加完整配置，然后开启配置的自动后台更新。模块使用者开启模块自动后台更新。GitHub更新与手机更新是两个环节：仓库发生提交后，手机仍需要刷新远程配置。iOS后台调度不保证立即更新，可手动更新。HTTPS解密需要自己的证书，完整配置仍默认关闭MITM。

## 自动更新内容

GitHub Actions 在 UTC 00:17、06:17、12:17、18:17 计划运行（日本时间09:17、15:17、21:17、03:17），也可在 Actions → Update Shadowrocket subscription → Run workflow 手动运行。

1. 刷新 ACL4SSR 的广告联盟、App广告、国内网页广告三份核心库。NobyDa仅作为有限国内SDK端点补充，不整库导入。
2. 将实际引用的远程规则集和脚本复制到本仓库 `upstream/`，生成文件引用本仓库路径。上游脚本或规则字节变化会成为本仓库提交。
3. 按域名后缀、关键词和CIDR去重，保留金融与认证排除设置，禁止重新膨胀到28万条。广告规则数量上限20,000。
4. 对下载的JavaScript只做语法检查，不执行。上游请求失败或脚本语法不通过时继续用最近的有效缓存版本；第一次没有缓存的引用会在报告中标记unavailable，保留原始引用，不宣称成功。
5. 重建 `dist/` 并验证微信读书保持启用、健康域名不被域名广告库拒绝。验证失败则不提交。无文件变化则不提交。

GitHub计划运行可能延迟，也可能受Actions关闭、仓库权限、使用额度或公共仓库长期无活动导致的停用影响。检查Actions最近一次成功记录确认运行状态。

更新范围是配置**实际引用的规则集、脚本和批准的核心库**。`profiles/`中经筛选的App原生URL/正文匹配器是固定策略快照；其他网站新增模块、更换接口路径或整份模块结构变化不会被未经比较自动合入。GKD的安卓界面点击选择器不参与小火箭构建。

## 修改与查看

- `profiles/full.conf`：自己的完整分流和策略模板。
- `profiles/adblock.sgmodule`、`profiles/enhance.sgmodule`：经比较的App请求处理模板。
- `profiles/app-rules.list`：保留的App广告分流增量。
- `sources.json`：批准的核心源和仓库地址。
- `dist/update-report.json`：各引用内容摘要、刷新或回退状态。

不要修改 `dist/`：下一次构建会覆盖。修改 `profiles/` 后工作流会自动重建。新增脚本路径或规则集URL也会进入引用刷新流程；上游脚本仍可改变App响应，应先人工审查新功能。

本地验证：

```sh
python3 tools/test_update.py
python3 tools/update.py --offline
```

正常刷新：

```sh
python3 tools/update.py
```

仓库已包含初始缓存与 `app-rules.list`，不需要再次运行 `--bootstrap`。更换仓库时修改sources.json；在GitHub Actions内使用实际GITHUB_REPOSITORY生成raw路径。

公开仓库内容只包含规则、配置与公开上游脚本，不要在profiles中加入节点密码、共享证书私钥、个人Cookie或Token。
