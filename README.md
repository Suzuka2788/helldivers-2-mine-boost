# Suzuka’s Mine Boost v1.0.1

v1.0.1 只改脚本，玩法、资源和写入字段与 v1.0.0 完全相同；GUID 不变，导入后替换 v1.0.0。
- 兼容：所有 kernel32/bcrypt 调用经 GetProcAddress 绑定为本脚本自己的签名，不再受其他模组同名 FFI 声明影响；与旧 AT Melta / Medium Trigger 脚本同时启用时不重复写入，并在日志记录 LEGACY_SCRIPT_ACTIVE；加载时没有 update 也能继续轮询。
- 加载：已验证 game.dll 通过 PE 头和文件大小识别（读 4 KB），不再每次对 15 MB 文件做 SHA-256；不匹配时退回 SHA-256，并复用其他 Suzuka 模组的哈希缓存。日志新增 IDENTITY 与 LOAD_MS。
- 运行：每次检查由 6 次内存读取减为 3 次（索引表与三行合并为一次读取），读取用固定缓冲区；检查帧避开 60/120/600 帧整倍数，减少与其他模组同帧叠加。日志新增 READS。

将已验证的 AT Melta Native Model 0.3.2 与 Mines Medium Trigger 0.1.1-preview2 合并为一个脚本。

- 反坦克地雷：ExplosionType 178 → 368，热熔末段伤害配置；原版外观、物理和触发门槛保持不变。
- 反步兵地雷：触发体型 Small → Medium。
- 燃烧地雷：触发体型 Small → Medium。

中体型门槛排除小体型单位（包括绝地潜兵和小型敌人），不是阵营过滤器。射击仍可引爆。数量、散布、冷却、布防和触发时间不变。热熔基础/耐久伤害 2000/2000、穿甲 7/7/7/0、内外半径 2.5/6 米；不是完整手投热熔的粘附或蓄热流程。不新增特效、不移除既有末段粒子。

关闭游戏，在管理器中停用旧 AT-Melta-Native-Model、Mines-Medium-Trigger，以及旧 Mine Deployer Swap / AT Melta 替换包，再导入本 ZIP，仅启用合并版。合并版使用独立 GUID，不会自动替换两个旧管理器条目。需要 Bingus Shared Loader v15+。

日志：%LOCALAPPDATA%\CowboyBingus\Helldivers2\Logs\TongzMinesCombined.log
正常状态 APPLIED_COMBINED_MINES，首次应用 WRITES=3；退出 RESTORED_ON_SHUTDOWN，RESTORES=3。三项修改共用一次定位、验证和恢复，避免两个旧脚本因同表修改互相拒绝。DLL、索引表或目标记录不匹配时拒写并记录原因。

包内热熔依赖资源沿用已验证 0.3.2 的原始字节，没有反坦克 unit/physics 覆盖。不自动安装、不写可执行内存、不调用游戏原生函数。

原功能已有验证；合并版需要游戏内复测三类地雷。日志只证明写入，不能替代实际触发与伤害观察。
