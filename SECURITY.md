# Security

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.0.3   | :white_check_mark: |
| 0.0.2   | :white_check_mark: |
| 0.0.1   | :x:                |

## Security Issues in v0.0.1

### ATLAS-SEC-2025-001: WebSocket and CORS Vulnerabilities

**Affected:** v0.0.1  
**Fixed:** v0.0.2

#### Issues Found

1. **WebSocket Origin Bypass**
   - Location: `node/main.go:93` and `api/main.go:119`
   - Issue: `CheckOrigin: func(r *http.Request) bool { return true }`
   - Impact: Any website can connect to WebSocket endpoints

2. **CORS Wildcard Configuration**
   - Location: API CORS middleware
   - Issue: Accepts requests from all origins (`*`)
   - Impact: Cross-origin requests allowed from any domain

3. **Missing Rate Limiting**
   - Location: Authentication endpoints
   - Issue: No limits on login attempts
   - Impact: Brute force attacks possible

#### Fixes in v0.0.2

- WebSocket connections now validate origin against configured endpoints
- CORS properly validates allowed origins
- Rate limiting added to login endpoint (30 requests/minute per IP)

#### Upgrade Recommendation

**Immediately upgrade from v0.0.1 to v0.0.2**

## Security Features

- JWT-based authentication
- Role-based access control (user/admin/sys)
- Password hashing with bcrypt
- WebSocket origin validation
- Rate limiting on authentication
- Secure CORS configuration

## Default Credentials

**Change immediately after installation:**
- Username: `admin`
- Password: `admin`

## Reporting Security Issues

Report security vulnerabilities privately to the maintainers rather than creating public issues.