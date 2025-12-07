# ChatGPT Team 邀请管理系统

支持多工作空间管理的 ChatGPT Team 邀请系统。

## 功能特性

- ✅ 支持多个 ChatGPT Team 工作空间管理
- ✅ 工作空间切换和选择
- ✅ 实时统计展示（座位使用、待邀请人数等）
- ✅ Cloudflare Turnstile 验证码保护
- ✅ 美观的现代化界面
- ✅ 响应式设计，支持各种设备

## 环境配置

### 方式一：JSON 格式（推荐）

```env
SECRET_KEY=your_secret_key
CF_TURNSTILE_SECRET_KEY=your_turnstile_secret
CF_TURNSTILE_SITE_KEY=your_turnstile_site_key

WORKSPACES=[
  {
    "id": "workspace1",
    "name": "Linux. do 团队",
    "authorization_token": "Bearer your_token_1",
    "account_id": "account_id_1"
  },
  {
    "id": "workspace2",
    "name": "开发团队",
    "authorization_token": "Bearer your_token_2",
    "account_id": "account_id_2"
  }
]
```

### 方式二：环境变量前缀

```env
SECRET_KEY=your_secret_key
CF_TURNSTILE_SECRET_KEY=your_turnstile_secret
CF_TURNSTILE_SITE_KEY=your_turnstile_site_key

WORKSPACE_1_NAME=Linux.do 团队
WORKSPACE_1_AUTHORIZATION_TOKEN=Bearer your_token_1
WORKSPACE_1_ACCOUNT_ID=account_id_1

WORKSPACE_2_NAME=开发团队
WORKSPACE_2_AUTHORIZATION_TOKEN=Bearer your_token_2
WORKSPACE_2_ACCOUNT_ID=account_id_2

WORKSPACE_3_NAME=测试团队
WORKSPACE_3_AUTHORIZATION_TOKEN=Bearer your_token_3
WORKSPACE_3_ACCOUNT_ID=account_id_3
```

### 方式三：单工作空间（向后兼容）

```env
SECRET_KEY=your_secret_key
CF_TURNSTILE_SECRET_KEY=your_turnstile_secret
CF_TURNSTILE_SITE_KEY=your_turnstile_site_key

AUTHORIZATION_TOKEN=Bearer your_token
ACCOUNT_ID=your_account_id
```

## 安装运行

```bash
# 安装依赖
pip install -r requirements.txt

# 运行服务
python main.py
```

默认运行在 `http://localhost:39001`

## 添加更多工作空间

只需在 `. env` 文件中继续添加：

```env
WORKSPACE_4_NAME=第四个团队
WORKSPACE_4_AUTHORIZATION_TOKEN=Bearer token4
WORKSPACE_4_ACCOUNT_ID=account_id_4

WORKSPACE_5_NAME=第五个团队
WORKSPACE_5_AUTHORIZATION_TOKEN=Bearer token5
WORKSPACE_5_ACCOUNT_ID=account_id_5
```

重启服务后即可生效，无需修改代码。

## 致谢

感谢校长和VV佬
