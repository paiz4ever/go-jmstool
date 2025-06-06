# JumpServer 终端直连远端

无需登录 JumpServer Web 端，在终端直接连接远端服务器

## 使用方法

1. 构建工具

   ```bash
   go build -o jmstool
   ```

2. 在工具的同级目录中添加 `config.yaml` 配置文件

   ```yaml
   access:
     key_id: <Api Key Id>
     secret: <Api Key Secret>
   ssh:
     host: <JumpServer部署的域名>
   ```

3. 直接运行工具

   ```bash
   ./jmstool -H <主机名>
   ```

## 参考

> [JumpServer 官方客户端](https://github.com/jumpserver/clients)

> [JumpServer 官方 API 文档](https://docs.jumpserver.org/zh/v3/dev/rest_api/#1-api)
