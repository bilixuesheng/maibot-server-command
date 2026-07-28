# 服务器命令执行

这是一个面向 MaiBot 1.x / `maibot-plugin-sdk` 2.x 的 Tool 插件。它向 Maisaka
提供 `run_server_command`，让 MaiBot 在低权限沙箱中运行 Ubuntu 命令，并提供
可选 ROOT 最高权限模式。

> **兼容性说明：本插件目前仅在 Ubuntu 上测试过，其他 Linux 发行版及操作系统
> 未经测试，不保证能够正常运行。**

## 使用前必须安装

使用插件前，请先在 Ubuntu 服务器执行：

```bash
sudo apt update
sudo apt install bubblewrap
```

> 如果未安装 Bubblewrap，低权限沙箱模式无法运行命令。

版本 1.0.10 将插件展示名称改为“服务器命令执行”，更新项目简介与 GitHub
仓库地址。权限、沙箱和 ROOT 模式逻辑均未改变。

版本 1.0.9 使用 `assets/icon.png` 作为 WebUI 插件图标，并保留 `terminal`
作为本地图标加载失败时的备用图标。命令权限、沙箱和 ROOT 模式逻辑均未改变。

版本 1.0.8 新增需要五重条件才能生效的可选 ROOT 最高权限模式：MaiBot 必须由
root 用户运行，并同时满足总开关、三次确认开关和最终数值 `1`。生效后命令不再
进入 Bubblewrap，而是以 root 在 `/root` 中运行。工具说明和每次返回结果都会
明确告诉麦麦当前拥有服务器最高权限，并要求它坚决拒绝高风险命令；插件还会在
Bash 启动前拦截已识别的破坏性磁盘操作、递归删除、关机重启、账号/防火墙变更、
敏感凭据访问及下载后直接执行等明显高风险类别。

ROOT 模式默认关闭。任一确认条件不满足，插件都会继续使用原来的低权限沙箱。
文字提醒和规则匹配无法识别所有经过混淆的危险 Shell 命令，因此 ROOT 模式仍然
属于极高风险能力，只应在管理员明确理解后使用。

版本 1.0.7 修复了 MaiBot 以 root 启动时所有命令均报
`bwrap: Can't chdir to /work: Permission denied` 的问题。Bubblewrap 先在隔离
环境的 `/` 中完成初始化，Ubuntu 自带的 `setpriv` 随后强制切换到
`nobody:nogroup`，低权限包装器成为 `0700` 沙箱目录的所有者后才进入 `/work`
并执行麦麦提供的 Bash 命令。无需放宽目录权限，也不会把 root 权限交给命令。

1.0.6 对服务器禁止普通用户 UID 映射的兼容修复仍然保留：root 仅用于建立
Bubblewrap 的挂载和进程隔离；命令不依赖用户命名空间或 UID 映射，并会清空
附加组、capabilities 与提权能力。文件系统安全边界不变。

命令的宿主机持久化读写范围固定为：

```text
<MaiBot 主程序目录>/maibot-command-file/
```

低权限模式不接受自定义工作目录，也不会在隔离失败时回退到普通
`subprocess`。绝对路径、`..`、Shell 重定向、管道和子 Shell 不靠字符串黑名单
判断，而是由 Linux 挂载命名空间限制：MaiBot 主程序及宿主机其他数据目录根本
不会被挂载进命令环境。

## 安装

要求：

- Ubuntu
- MaiBot 1.x
- `maibot-plugin-sdk` 2.x
- Bubblewrap
- util-linux（Ubuntu 默认自带，用于 `/usr/bin/setpriv`）

将整个插件目录放入：

```text
<MaiBot>/plugins/maibot-server-command/
```

最终至少应有：

```text
<MaiBot>/plugins/maibot-server-command/
├── _manifest.json
├── assets/
│   └── icon.png
├── executor.py
├── plugin.py
└── README.md
```

启动或重载 MaiBot。Runner 会根据插件的 `config_model` 自动生成
`config.toml`，插件还会自动创建
`<MaiBot>/maibot-command-file/`。MaiBot 可以由 root 启动。插件让受信任的
Bubblewrap 以 root 建立挂载、PID、IPC 和 UTS 隔离，然后在执行 Bash 前通过
`/usr/bin/setpriv` 清空附加组，并不可逆地降权到 Ubuntu 自带的
`nobody:nogroup`（通常为 UID/GID 65534）；命令不会继承 root 权限。沙箱目录
及其中已有内容会被安全检查后转交给该低权限用户，目录权限固定为 `0700`。即使
MaiBot 安装在 `/root` 下，插件也通过预先打开的目录句柄挂载沙箱，不会向命令
开放 `/root`。

## 低权限沙箱安全边界

- 使用 Bubblewrap 的挂载、PID、IPC、UTS、cgroup 和网络命名空间。普通用户
  启动 MaiBot 时还使用用户命名空间；root 启动模式无需用户命名空间或 UID 映射。
- 唯一映射到宿主机的可写目录是 `maibot-command-file`，在命令环境中显示为
  `/work`，并固定作为当前目录。
- `/usr/bin`、`/usr/sbin`、`/usr/lib` 和 `/usr/share` 只读挂载，以便使用
  Ubuntu 自带命令；`/usr/local`、`/etc`、`/home`、MaiBot 主程序等均不挂载。
- 联网默认关闭，此时网络命名空间不包含宿主机网络接口。
- 开启联网后，命令共享宿主机网络，可访问公网、内网以及宿主机本机监听的服务；
  文件系统隔离、命令降权和资源限制仍然保持不变。
- 清空继承环境，只设置最小 `PATH`、`HOME` 和 `LANG`。
- 丢弃 Linux capabilities 并启用 `no_new_privs`；普通用户模式还会禁止嵌套
  创建用户命名空间。
- 当 MaiBot 以 root 启动时，只有受信任的 Bubblewrap 建立隔离阶段保留必要
  权限；它启动的固定 `setpriv` 包装器会在 Bash 解析命令前切换到
  `nobody:nogroup`、清空附加组及全部 capabilities。任何一步失败，命令都不会
  执行。
- 设置运行时间、输出、虚拟内存、单文件大小、文件描述符及进程数限制。
- 执行前拒绝沙箱内已有的硬链接、FIFO、Socket 和设备文件，避免借预置对象触达
  沙箱外资源。

需要注意：命令可以自由删除或覆盖 `maibot-command-file` **内部**的数据，这正是
该插件授权给模型的沙箱范围。重要数据不要放入该目录。虽然插件支持由 root 启动
MaiBot，但这只解决本插件命令的降权与隔离；其他插件仍会继承 MaiBot 主进程权限。
管理员应对服务器做常规备份和磁盘配额。

## ROOT 最高权限模式

此模式默认关闭。只有下面五项全部满足才会生效：

1. MaiBot 主进程的实际用户为 root（有效 UID 为 0）。
2. 打开“关闭沙箱并启用 ROOT 最高权限”。
3. 依次打开第一次、第二次和第三次确认。
4. 将“最终确认”输入框中的 `0` 手动改为 `1`。

生效后的行为：

- 不启动 Bubblewrap，也不降权到 `nobody`。
- Bash 的实际 UID/GID 为 `0:0`，固定工作目录为 `/root`。
- 每次工具结果最前面都有“ROOT 最高权限”警告，并要求麦麦拒绝高风险命令。
- 日志以醒目的高危级别记录模式启用、准备执行、成功、失败和拒绝。
- 超时、输出、内存、单文件大小和进程数限制仍然保留。
- 插件在执行前拒绝已识别的明显高风险类别，且不会把原始命令或 Token 写入日志。

规则匹配只是一层额外防护，不能安全理解任意 Bash、脚本语言或混淆命令。ROOT
进程理论上能够读取、修改或删除服务器上的任何数据，也能访问网络和本机服务；
管理员必须自行做好备份、最小化服务器凭据，并只在必要时短期开启。

## 配置

首次加载后，MaiBot 会根据 `config_model` 生成 `config.toml`。可在 WebUI 调整：

- 是否启用工具
- 是否允许命令联网（默认关闭）
- 单次命令超时
- 输出保留上限
- 每进程虚拟内存上限
- 单文件大小上限
- 进程数上限
- ROOT 最高权限总开关
- 第一次、第二次和第三次确认开关
- 最终数字确认输入框

WebUI 中会显示“启用命令工具”“允许命令联网”“命令超时时间（秒）”等中文
名称，并在每项下面显示中文说明。运行时 `config.toml` 不随仓库分发，避免安装
或升级时覆盖用户设置；它会在首次加载后由 Runner 根据中文配置模型生成。

代码中另有不可由配置突破的硬上限。

要允许麦麦使用 `curl`、`wget` 等联网命令，请在 WebUI 打开“是否允许沙箱命令
访问网络”，或在插件配置中设置：

```toml
[plugin]
config_version = "1.0.10"

[sandbox]
network_enabled = true
```

保存配置后，日志会显示 `network_enabled=True`。开启联网等于授权麦麦访问公网、
服务器内网以及本机网络服务，也允许它上传沙箱内的数据；请不要把密码、Token 或
其他敏感文件放进 `maibot-command-file`。

ROOT 模式的完整配置如下。请注意：下列值全部开启会关闭命令沙箱。

```toml
[root_mode]
enabled = true
confirmation_1 = true
confirmation_2 = true
confirmation_3 = true
final_confirmation = 1
```

如果 MaiBot 不是 root，或其中任一值不满足，日志会说明未生效原因，命令仍使用
低权限沙箱。要关闭 ROOT 模式，只需把 `enabled` 改回 `false`；建议同时把三个
确认开关和最终数值恢复为默认值。

## 测试

在插件目录运行：

```bash
python -m pytest -q
```

由于 CI 或容器环境可能禁止创建所有命名空间，单元测试检查路径解析、Manifest
组件、root/普通用户两种参数构造、降权参数及逃逸防护；部署后的实际隔离是否
可用，应再让 MaiBot 执行：

```bash
pwd
printf 'hello\n' > hello.txt
ls -la
```

预期工作目录为 `/work`，文件会出现在
`<MaiBot>/maibot-command-file/hello.txt`。再执行 `ls /etc` 应显示路径不存在；
在默认配置下联网命令应失败。

开启 `network_enabled` 后，可测试：

```bash
curl -I --max-time 10 https://example.com
```

麦麦会收到退出码、标准输出、标准错误、是否超时和输出是否被截断。服务器日志会
记录命令开始、成功、非零退出、超时或沙箱异常；日志只记录命令摘要 ID，不记录
完整命令，避免将命令中的密码或 Token 写入日志。
