# g-jwt

创建jwt密钥：
   openssl rand -hex 32

1. 空 token（游客模式）
   - 如果 tokenString == ""，返回游客信息，不报错
   - UserID = 0, IsGuest = true 
   - 
   - 非空 token（必须验证通过）
   - 如果 token 存在但无效：返回错误
   - 如果 token 存在但过期：返回错误
   - 如果 token 存在但设备ID不匹配：返回错误
   - 如果 token 有效：返回用户信息，IsGuest = false
