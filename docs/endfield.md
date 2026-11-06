# 终末地 Bundle / VFS 支持

此分支基于 UnityPy 上游 master `417d59522a998fdee9a9c2b29fe35f3063222457`，保留完整 Git 历史。

安装（仓库已建立 `.venv`）：

```sh
python -m pip install -e '.[endfield]'
```

## 按需读取原始 VFS

```python
import UnityPy

vfs = UnityPy.EndfieldVFS('/Users/moeyinlo/AKEVfsData')
# 只解析 Bundle / InitBundle 的 .blc 索引，不加载全部 AB。
names = list(vfs.entries)
print(len(names), names[:5])

env = vfs.load(names[:1])  # 也可传单个完整逻辑文件名字符串
for obj in env.objects:
    print(obj.path_id, obj.type.name)
    data = obj.parse_as_dict()
    if obj.type.name == 'Texture2D':
        obj.parse_as_object().image.save('texture.png')

# 解密后的单个逻辑 AB 可交给普通 UnityPy.load，或保存供后续读取。
raw = vfs.read(names[0])
env = UnityPy.load(raw)
```

`EndfieldVFS` 接受 VFS 的父目录、VFS 目录、Bundle 分组目录、`.blc` 路径、`.chk` 路径。单个 CHK 必须有同目录的分组 BLC；CHK 本身没有足够的条目边界和解密 nonce 信息。

快捷方法：

```python
vfs = UnityPy.EndfieldVFS('/path/to/VFS')
name = next(iter(vfs.entries))
env = UnityPy.load_endfield('/path/to/VFS', bundle_names=[name])

# 单个解密后的 Endfield AB：自动识别自定义头部。
env = UnityPy.load('/path/to/decrypted.ab')

# 原始 BLC / CHK / VFS 目录：自动加载该输入覆盖的全部 Bundle。
env = UnityPy.load('/path/to/VFS/0CE8FA57/0CE8FA57.blc')
```

本机主 Bundle 索引含 272,533 个条目；日常分析建议使用 `EndfieldVFS.load(names)` 按需加载。`load_endfield` 不传 `bundle_names` 也会加载全部条目。只加载所选 AB；跨 Bundle 的 PPtr 需要把相关 Bundle 一起加载到同一环境，例如 `vfs.load(more_names, environment=env)`。当前没有 BundleManifest 依赖自动发现功能。

## 格式范围

- 外层：Bundle (`7064D8E2`) / InitBundle (`0CE8FA57`)，BLC layout 0–5（v5 的 64 位 Patch tag），CHK 偏移定位，IETF ChaCha20 counter=1，默认校验解密后的 MD5。
- 默认使用 PC key；Android 可显式指定 `from UnityPy.endfield import ANDROID_KEY` 后传 `key=ANDROID_KEY`。Android key 是配置入口，本次真实资源验证使用 PC 数据。
- 内层：48 字节聚合容器头、`encFlags=8`、前置 metadata、metadata raw / 加密 LZ4、payload raw / 加密 LZ4Inv、自定义 S-box 采样流变换、CAB 和 `.resS` 注册。
- Table、JsonData、Lua、Audio、BundleManifest 等不在支持范围。未知加密标志、末尾 metadata、未知压缩模式会明确报错。
- 输出上限为每个聚合容器 512 MiB；损坏、截断、越界、MD5 不符均报错。
- 读取后使用原有 `env.objects`、`env.assets`、`env.container`、`parse_as_dict()`、`parse_as_object()` 等接口。内嵌 TypeTree 支持自定义 MonoBehaviour 字段。
- VFS / 聚合容器为只读；不提供游戏可接受的重打包、重加密功能。聚合容器调用 `save()` 会抛出 `NotImplementedError`。

原版 UnityPy 的资源转换限制仍适用。例如此次 PC 抽样中 RG16 的图像导出触发上游转换器 `KeyError: 'raw'`，部分 RGBAHalf 数据超出上游字节转换范围；这些对象的 TypeTree 解析成功。AB 加载成功不等于所有资源都可导出成 PNG。

格式实现参考本机 Perlica 的 VfsReader / AggregateFormat / AggregateCipher / UnityCompression；保留相应 MIT 许可于 `UnityPy/licenses/endfield-bundle-parser-MIT.txt`。

## 验证

```sh
python -m pytest tests/test_endfield.py -q
python -m pytest -q
ruff check
ruff format --check
```

`tests/fixtures/endfield/aggregate.bin` 为 Perlica 已有的生产格式固定样本（SHA256 `65a88346480bf8f3ce93e7c9e33f7e186539d8611b5cc4ae744de510a320ede9`），包含一个 CAB 和资源流。LZ4Inv 固定向量输出 `abcabcabc`。测试覆盖 bytes / stream / path 自动识别、对象与资源流、v0/v4/v5 索引、明文/加密 CHK、父目录/分组/BLC/CHK 输入、MD5 与截断等错误。

真实 PC 抽样与回归结果见 `endfield-validation.json`。这份报告只针对记录的本地资源和抽样，不代表全部资源版本或全部 AB 已验证。
