import './style.css'
import { NodeTerminal, type TerminalOptions } from './terminal'
import { SimpleTerminal, type SimpleTerminalOptions } from './simple-terminal'

interface Node {
  id: string
  name: string
  url: string
  key: string
  status: string
  last_seen: string
  created_at: string
  system_info: string
}

interface SystemInfo {
  os: string
  arch: string
  cpu_usage: number
  ram_usage: number
  ram_total: number
  disk_usage: number
  disk_total: number
  uptime: number
}

interface User {
  id: string
  username: string
  role: string
  created_at: string
}

interface AuthResponse {
  token: string
  user: User
  expires: number
}

interface MeResponse {
  user: User
}

class AtlasPanel {
  private apiUrl = 'http://localhost:8080'
  private authToken: string | null = null
  private currentUser: User | null = null
  private currentTerminal: NodeTerminal | SimpleTerminal | null = null
  private useSimpleTerminal = true // Use simple terminal by default

  private getAuthHeaders(): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json'
    }
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`
    }
    return headers
  }

  async login(username: string, password: string): Promise<void> {
    const response = await fetch(`${this.apiUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    })
    
    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Login failed')
    }
    
    const data: AuthResponse = await response.json()
    this.authToken = data.token
    this.currentUser = data.user
    
    localStorage.setItem('atlas_token', data.token)
    localStorage.setItem('atlas_user', JSON.stringify(data.user))
    localStorage.setItem('atlas_expires', data.expires.toString())
  }

  async logout(): Promise<void> {
    if (this.authToken) {
      await fetch(`${this.apiUrl}/auth/logout`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
      })
    }
    
    this.authToken = null
    this.currentUser = null
    localStorage.removeItem('atlas_token')
    localStorage.removeItem('atlas_user')
    localStorage.removeItem('atlas_expires')
  }

  checkAuth(): boolean {
    const token = localStorage.getItem('atlas_token')
    const user = localStorage.getItem('atlas_user')
    const expires = localStorage.getItem('atlas_expires')
    
    if (!token || !user || !expires) {
      return false
    }
    
    if (Date.now() / 1000 > parseInt(expires)) {
      this.logout()
      return false
    }
    
    this.authToken = token
    this.currentUser = JSON.parse(user)
    
    return true
  }

  async getCurrentUser(): Promise<MeResponse> {
    const response = await fetch(`${this.apiUrl}/me`, {
      headers: this.getAuthHeaders(),
    })
    
    if (!response.ok) {
      throw new Error('Failed to get user info')
    }
    
    return response.json()
  }

  async addNode(name: string, url: string): Promise<Node> {
    const response = await fetch(`${this.apiUrl}/nodes`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ name, url }),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        this.showLoginPage()
        throw new Error('Authentication required')
      }
      throw new Error('Failed to add node')
    }
    
    return response.json()
  }

  async getNodes(): Promise<Node[]> {
    const response = await fetch(`${this.apiUrl}/nodes`, {
      headers: this.getAuthHeaders(),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        this.showLoginPage()
        throw new Error('Authentication required')
      }
      throw new Error('Failed to fetch nodes')
    }
    
    return response.json()
  }

  async deleteNode(id: string): Promise<void> {
    const response = await fetch(`${this.apiUrl}/nodes/${id}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        this.showLoginPage()
        throw new Error('Authentication required')
      }
      throw new Error('Failed to delete node')
    }
  }

  updateStats(nodes: Node[]): void {
    const totalNodes = nodes.length
    const onlineNodes = nodes.filter(node => node.status === 'online').length
    const offlineNodes = totalNodes - onlineNodes

    document.getElementById('total-nodes')!.textContent = totalNodes.toString()
    document.getElementById('online-nodes')!.textContent = onlineNodes.toString()
    document.getElementById('offline-nodes')!.textContent = offlineNodes.toString()
    document.getElementById('status-ratio')!.textContent = `${onlineNodes}/${totalNodes}`
  }

  renderDashboardNodes(nodes: Node[]): void {
    const dashboardNodesList = document.getElementById('dashboard-nodes-list')!
    
    if (nodes.length === 0) {
      dashboardNodesList.innerHTML = '<div class="empty-state">No nodes configured yet.</div>'
      return
    }

    const recentNodes = nodes.slice(0, 5)
    dashboardNodesList.innerHTML = `
      <table class="nodes-table">
        <thead>
          <tr>
            <th>Node Name</th>
            <th>URL</th>
            <th>Status</th>
            <th>CPU</th>
            <th>RAM</th>
            <th>Disk</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          ${recentNodes.map(node => {
            const sysInfo = this.parseSystemInfo(node.system_info)
            const isOffline = node.status === 'offline'
            return `
              <tr>
                <td class="node-name">${node.name}</td>
                <td class="node-url">${node.url}</td>
                <td><span class="status ${node.status}">${node.status}</span></td>
                <td class="metric">${isOffline ? '--' : (sysInfo ? sysInfo.cpu_usage.toFixed(1) + '%' : 'N/A')}</td>
                <td class="metric">${isOffline ? '--' : (sysInfo ? sysInfo.ram_usage.toFixed(1) + '%' : 'N/A')}</td>
                <td class="metric">${isOffline ? '--' : (sysInfo ? sysInfo.disk_usage.toFixed(1) + '%' : 'N/A')}</td>
                <td class="last-seen">${this.formatLastSeen(node.last_seen)}</td>
              </tr>
            `
          }).join('')}
        </tbody>
      </table>
    `
  }

  parseSystemInfo(systemInfoStr: string): SystemInfo | null {
    try {
      if (!systemInfoStr || systemInfoStr === '{}') return null
      return JSON.parse(systemInfoStr) as SystemInfo
    } catch {
      return null
    }
  }

  formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  formatUptime(seconds: number): string {
    if (!seconds || seconds === 0) return 'Unknown'
    
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    
    if (days > 0) return `${days} day${days > 1 ? 's' : ''}, ${hours} hour${hours !== 1 ? 's' : ''}`
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''}, ${mins} minute${mins !== 1 ? 's' : ''}`
    if (mins > 0) return `${mins} minute${mins > 1 ? 's' : ''}`
    return 'Less than a minute'
  }

  formatLastSeen(lastSeen: string): string {
    if (!lastSeen) return 'Never'
    
    const date = new Date(lastSeen)
    
    // Check if the date is invalid
    if (isNaN(date.getTime())) {
      return 'Never'
    }
    
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    
    // If the difference is negative or extremely large, treat as never seen
    if (diffMs < 0 || diffMs > 365 * 24 * 60 * 60 * 1000) {
      return 'Never'
    }
    
    const diffMins = Math.floor(diffMs / 60000)
    
    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    
    const diffHours = Math.floor(diffMins / 60)
    if (diffHours < 24) return `${diffHours}h ago`
    
    const diffDays = Math.floor(diffHours / 24)
    if (diffDays > 365) return 'Never'
    
    return `${diffDays}d ago`
  }

  renderNodes(nodes: Node[]): void {
    const nodesList = document.getElementById('nodes-list')!
    const isAdmin = this.currentUser?.role === 'admin' || this.currentUser?.role === 'sys'
    
    if (nodes.length === 0) {
      nodesList.innerHTML = '<div class="empty-state">No nodes yet. Add one above.</div>'
      return
    }

    nodesList.innerHTML = `
      <table class="nodes-table">
        <thead>
          <tr>
            <th>Node Name</th>
            <th>Status</th>
            <th>OS</th>
            <th>CPU</th>
            <th>RAM</th>
            <th>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${nodes.map(node => {
            const sysInfo = this.parseSystemInfo(node.system_info)
            const isOffline = node.status === 'offline'
            return `
              <tr>
                <td class="node-name">
                  <a href="/node/${node.id}" class="node-link">${node.name}</a>
                </td>
                <td><span class="status ${node.status}">${node.status}</span></td>
                <td class="os-info">${isOffline ? '--' : (sysInfo ? `${sysInfo.os} ${sysInfo.arch}` : 'Unknown')}</td>
                <td class="metric">${isOffline ? '--' : (sysInfo ? sysInfo.cpu_usage.toFixed(1) + '%' : 'N/A')}</td>
                <td class="metric">${isOffline ? '--' : (sysInfo ? sysInfo.ram_usage.toFixed(1) + '%' : 'N/A')}</td>
                <td class="last-seen">${this.formatLastSeen(node.last_seen)}</td>
                <td class="actions">
                  <button class="view-btn" data-id="${node.id}">View</button>
                  ${isAdmin ? `<button class="delete-btn" data-id="${node.id}">Delete</button>` : ''}
                </td>
              </tr>
            `
          }).join('')}
        </tbody>
      </table>
    `

    nodesList.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault()
        const id = (e.target as HTMLElement).dataset.id!
        await this.deleteNode(id)
        this.loadNodes()
      })
    })

    nodesList.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault()
        const id = (e.target as HTMLElement).dataset.id!
        this.showPage(`node-${id}`)
      })
    })

    nodesList.querySelectorAll('.node-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault()
        const href = (e.target as HTMLElement).getAttribute('href')!
        const id = href.split('/').pop()!
        this.showPage(`node-${id}`)
      })
    })
  }

  async loadNodes(): Promise<void> {
    if (!this.checkAuth()) {
      this.showLoginPage()
      return
    }
    
    try {
      const nodes = await this.getNodes()
      this.updateStats(nodes)
      this.renderDashboardNodes(nodes)
      this.renderNodes(nodes)
    } catch (error) {
      console.error('Failed to load nodes:', error)
      if (error instanceof Error && error.message === 'Authentication required') {
        this.showLoginPage()
      }
    }
  }

  async showPage(page: string): Promise<void> {
    if (page !== 'login' && !this.checkAuth()) {
      this.showLoginPage()
      return
    }
    
    // Get current user info from server
    if (page !== 'login') {
      try {
        const userInfo = await this.getCurrentUser()
        this.currentUser = userInfo.user
        
        // Update localStorage with fresh user data
        localStorage.setItem('atlas_user', JSON.stringify(userInfo.user))
      } catch (error) {
        // If /me fails, user is probably not authenticated
        this.showLoginPage()
        return
      }
    }
    
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'))
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'))
    
    if (page.startsWith('node-')) {
      this.showNodePage(page.replace('node-', ''))
      return
    }
    
    document.getElementById(`${page}-page`)?.classList.add('active')
    document.querySelector(`[data-page="${page}"]`)?.classList.add('active')
    
    const titles: Record<string, string> = {
      dashboard: 'Dashboard',
      nodes: 'Node Management',
      users: 'User Management',
      account: 'Account Settings',
      login: 'Login'
    }
    
    document.getElementById('page-title')!.textContent = titles[page] || page
    
    // Load page-specific data
    if (page === 'users') {
      this.loadUsers()
    }
    
    // Don't change URL if we're showing the login page
    if (page !== 'login') {
      window.history.replaceState({ page }, '', page === 'dashboard' ? '/' : `/${page}`)
    }
  }

  showLoginPage(): void {
    // Redirect to root path when showing login
    window.history.replaceState({}, '', '/')
    
    // Hide the main app content
    const sidebar = document.querySelector('.sidebar') as HTMLElement
    const mainContent = document.querySelector('.main-content') as HTMLElement
    
    if (sidebar) sidebar.style.display = 'none'
    if (mainContent) mainContent.style.display = 'none'
    
    let loginPage = document.getElementById('login-page')
    if (!loginPage) {
      this.createLoginPage()
    }
  }

  async showNodePage(nodeId: string): Promise<void> {
    try {
      const nodes = await this.getNodes()
      const node = nodes.find(n => n.id === nodeId)
      
      if (!node) {
        this.showPage('nodes')
        return
      }

      this.renderNodePage(node)
      document.getElementById('node-detail-page')?.classList.add('active')
      document.getElementById('page-title')!.textContent = `Node: ${node.name}`
      
      window.history.pushState({ page: `node-${nodeId}` }, '', `/node/${nodeId}`)
    } catch (error) {
      console.error('Failed to load node details:', error)
      this.showPage('nodes')
    }
  }

  renderNodePage(node: Node): void {
    const nodeDetailPage = document.getElementById('node-detail-page')
    if (!nodeDetailPage) {
      this.createNodeDetailPage()
    }

    const isAdmin = this.currentUser?.role === 'admin' || this.currentUser?.role === 'sys'
    const content = document.querySelector('#node-detail-page .content-body')!
    content.innerHTML = `
      <div class="node-header">
        <div class="node-title">
          <h3>${node.name}</h3>
          <span class="status ${node.status}">${node.status}</span>
        </div>
        <div class="node-actions">
          <button class="back-btn" onclick="panel.showPage('nodes')">← Back to Nodes</button>
          ${isAdmin ? `<button class="delete-btn" data-id="${node.id}">Delete Node</button>` : ''}
        </div>
      </div>

      <div class="node-details-grid">
        <div class="detail-card">
          <h4>Connection Details</h4>
          <div class="detail-row">
            <span class="label">URL:</span>
            <span class="value">${node.url}</span>
          </div>
          <div class="detail-row">
            <span class="label">Status:</span>
            <span class="value status ${node.status}">${node.status}</span>
          </div>
          <div class="detail-row">
            <span class="label">Last Seen:</span>
            <span class="value">${this.formatLastSeen(node.last_seen)}</span>
          </div>
          <div class="detail-row">
            <span class="label">Created:</span>
            <span class="value">${new Date(node.created_at).toLocaleString()}</span>
          </div>
        </div>

        ${this.renderSystemInfoCard(node.system_info, node.status)}

        <div class="detail-card">
          <h4>Authentication</h4>
          <div class="detail-row">
            <span class="label">Node ID:</span>
            <span class="value mono">${node.id}</span>
          </div>
          <div class="detail-row">
            <span class="label">Access Key:</span>
            <span class="value mono key-hidden" title="Hover to reveal key, click to copy" onclick="panel.copyAccessKey('${node.key}', this)">
              <div class="copy-notification">Copied!</div>
              <span class="key-value">${node.key}</span>
              <span class="key-placeholder">••••••••••••••••••••••••••••••••••••</span>
            </span>
          </div>
        </div>

        <div class="detail-card">
          <h4>Configuration</h4>
          <div class="config-section">
            <div class="config-header">
              <h5>Node Agent Config</h5>
              <button class="copy-btn" onclick="panel.copyConfig('${node.key}')">
                <i class="fas fa-copy"></i>
              </button>
            </div>
            <div class="config-block">
              <pre><code id="config-json"><span class="json-brace">{</span>
  <span class="json-key">"api_endpoint"</span><span class="json-colon">:</span> <span class="json-string">"${window.location.origin.replace('5173', '8080')}"</span><span class="json-comma">,</span>
  <span class="json-key">"key"</span><span class="json-colon">:</span> <span class="json-string">"${node.key}"</span>
<span class="json-brace">}</span></code></pre>
            </div>
          </div>
        </div>

        ${isAdmin && node.status === 'online' ? `
        <div class="detail-card">
          <h4>Remote Shell Access</h4>
          <div class="shell-access-section">
            <div class="shell-access-warning">
              <i class="fas fa-exclamation-triangle"></i>
              <div>
                <strong>Security Warning:</strong> Shell access provides full control over the remote system. 
                Only use this feature if you trust the node and understand the security implications.
              </div>
            </div>
            <button class="shell-btn" onclick="panel.openShell('${node.id}', '${node.name}')">
              <i class="fas fa-terminal"></i>
              Open Shell
            </button>
          </div>
        </div>
        ` : ''}
      </div>
    `

    if (isAdmin) {
      content.querySelector('.delete-btn')?.addEventListener('click', async (e) => {
        const id = (e.target as HTMLElement).dataset.id!
        if (confirm('Are you sure you want to delete this node?')) {
          await this.deleteNode(id)
          this.showPage('nodes')
        }
      })
    }
  }

  renderSystemInfoCard(systemInfoStr: string, nodeStatus: string): string {
    const sysInfo = this.parseSystemInfo(systemInfoStr)
    const isOffline = nodeStatus === 'offline'
    
    if (!sysInfo || isOffline) {
      return `
        <div class="detail-card">
          <h4>System Information</h4>
          <div class="detail-row">
            <span class="label">Operating System:</span>
            <span class="value">${isOffline ? '--' : 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="label">Uptime:</span>
            <span class="value">${isOffline ? '--' : 'Unknown'}</span>
          </div>
          <div class="detail-row">
            <span class="label">CPU Usage:</span>
            <span class="value">${isOffline ? '--' : 'N/A'}</span>
          </div>
          <div class="detail-row">
            <span class="label">RAM Usage:</span>
            <span class="value">${isOffline ? '--' : 'N/A'}</span>
          </div>
          <div class="detail-row">
            <span class="label">Disk Usage:</span>
            <span class="value">${isOffline ? '--' : 'N/A'}</span>
          </div>
        </div>
      `
    }

    const isUnsupportedOS = sysInfo.os.toLowerCase().includes('windows') || 
                           sysInfo.os.toLowerCase().includes('darwin') ||
                           sysInfo.os.toLowerCase().includes('macos')

    return `
      <div class="detail-card">
        ${isUnsupportedOS ? `
          <div class="warning-banner">
            <i class="fas fa-exclamation-triangle"></i>
            This OS is not officially supported by Atlas Panel, use with caution. Some features may be buggy.
          </div>
        ` : ''}
        <h4>System Information</h4>
        <div class="detail-row">
          <span class="label">Operating System:</span>
          <span class="value">${sysInfo.os} (${sysInfo.arch})</span>
        </div>
        <div class="detail-row">
          <span class="label">Uptime:</span>
          <span class="value">${this.formatUptime(sysInfo.uptime)}</span>
        </div>
        <div class="detail-row">
          <span class="label">CPU Usage:</span>
          <span class="value">
            <div class="metric-bar">
              <div class="metric-fill cpu" style="width: ${Math.min(sysInfo.cpu_usage, 100)}%"></div>
              <span class="metric-text">${sysInfo.cpu_usage.toFixed(1)}%</span>
            </div>
          </span>
        </div>
        <div class="detail-row">
          <span class="label">RAM Usage:</span>
          <span class="value">
            <div class="metric-bar">
              <div class="metric-fill ram" style="width: ${Math.min(sysInfo.ram_usage, 100)}%"></div>
              <span class="metric-text">${sysInfo.ram_usage.toFixed(1)}% of ${this.formatBytes(sysInfo.ram_total)}</span>
            </div>
          </span>
        </div>
        <div class="detail-row">
          <span class="label">Disk Usage:</span>
          <span class="value">
            <div class="metric-bar">
              <div class="metric-fill disk" style="width: ${Math.min(sysInfo.disk_usage, 100)}%"></div>
              <span class="metric-text">${sysInfo.disk_usage.toFixed(1)}% of ${this.formatBytes(sysInfo.disk_total)}</span>
            </div>
          </span>
        </div>
      </div>
    `
  }

  createNodeDetailPage(): void {
    const mainContent = document.querySelector('.main-content .content-body')!
    const nodeDetailPage = document.createElement('div')
    nodeDetailPage.id = 'node-detail-page'
    nodeDetailPage.className = 'page'
    nodeDetailPage.innerHTML = '<div class="content-body"></div>'
    mainContent.appendChild(nodeDetailPage)
  }

  handleNavigation(): void {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const page = item.getAttribute('data-page')!
        window.location.href = page === 'dashboard' ? '/' : `/${page}`
      })
    })

    document.getElementById('logout-btn')?.addEventListener('click', async () => {
      await this.logout()
      window.location.href = '/'
    })

    // Load the correct page based on current URL
    this.initializePage()
  }

  async initializePage(): Promise<void> {
    const path = window.location.pathname
    
    if (path === '/' || path === '') {
      if (!this.checkAuth()) {
        this.showLoginPage()
      } else {
        await this.showPage('dashboard')
      }
    } else if (path === '/nodes') {
      await this.showPage('nodes')
    } else if (path === '/users') {
      await this.showPage('users')
    } else if (path === '/account') {
      await this.showPage('account')
    } else if (path.startsWith('/node/')) {
      const nodeId = path.split('/').pop()!
      await this.showPage(`node-${nodeId}`)
    } else {
      // Unknown path, redirect to dashboard
      if (!this.checkAuth()) {
        window.location.href = '/'
      } else {
        window.location.href = '/'
      }
    }
  }

  init(): void {
    this.handleNavigation()
    this.updateSidebar()
    this.setupFormListeners()

    if (!this.checkAuth()) {
      this.showLoginPage()
      return
    }

    this.loadNodes()
    setInterval(() => this.loadNodes(), 5000)
  }

  setupFormListeners(): void {
    // Password change form - always available
    const passwordForm = document.getElementById('change-password-form') as HTMLFormElement
    if (passwordForm) {
      const currentPasswordInput = document.getElementById('current-password') as HTMLInputElement
      const newPasswordInput = document.getElementById('new-password') as HTMLInputElement
      const passwordMessage = document.getElementById('password-message') as HTMLElement

      passwordForm.addEventListener('submit', async (e) => {
        e.preventDefault()
        passwordMessage.style.display = 'none'
        
        try {
          await this.changePassword(currentPasswordInput.value, newPasswordInput.value)
          currentPasswordInput.value = ''
          newPasswordInput.value = ''
          
          passwordMessage.textContent = 'Password changed successfully!'
          passwordMessage.style.background = '#d1ecf1'
          passwordMessage.style.color = '#0c5460'
          passwordMessage.style.display = 'block'
          
          setTimeout(() => {
            passwordMessage.style.display = 'none'
          }, 3000)
        } catch (error) {
          passwordMessage.textContent = error instanceof Error ? error.message : 'Failed to change password'
          passwordMessage.style.background = '#f8d7da'
          passwordMessage.style.color = '#721c24'
          passwordMessage.style.display = 'block'
        }
      })
    }

    // Node form - only for authenticated users
    const nodeForm = document.getElementById('add-node-form') as HTMLFormElement
    if (nodeForm) {
      const nameInput = document.getElementById('node-name') as HTMLInputElement
      const urlInput = document.getElementById('node-url') as HTMLInputElement

      nodeForm.addEventListener('submit', async (e) => {
        e.preventDefault()
        
        try {
          await this.addNode(nameInput.value, urlInput.value)
          nameInput.value = ''
          urlInput.value = ''
          this.loadNodes()
        } catch (error) {
          console.error('Failed to add node:', error)
        }
      })
    }

    // User form - only for authenticated users
    const userForm = document.getElementById('add-user-form') as HTMLFormElement
    if (userForm) {
      const usernameInput = document.getElementById('user-username') as HTMLInputElement
      const passwordInput = document.getElementById('user-password') as HTMLInputElement
      const roleSelect = document.getElementById('user-role') as HTMLSelectElement

      userForm.addEventListener('submit', async (e) => {
        e.preventDefault()
        
        try {
          await this.createUser(usernameInput.value, passwordInput.value, roleSelect.value)
          usernameInput.value = ''
          passwordInput.value = ''
          roleSelect.value = ''
          this.loadUsers()
        } catch (error) {
          console.error('Failed to create user:', error)
        }
      })
    }
  }

  copyConfig(nodeKey: string): void {
    const config = {
      api_endpoint: window.location.origin.replace('5173', '8080'),
      key: nodeKey
    }
    
    const configText = JSON.stringify(config, null, 2)
    
    navigator.clipboard.writeText(configText).then(() => {
      const copyBtn = document.querySelector('.copy-btn')
      if (copyBtn) {
        const originalContent = copyBtn.innerHTML
        copyBtn.innerHTML = '<i class="fas fa-check"></i>'
        copyBtn.classList.add('copied')
        
        setTimeout(() => {
          copyBtn.innerHTML = originalContent
          copyBtn.classList.remove('copied')
        }, 2000)
      }
    }).catch(() => {
      // Fallback for browsers that don't support clipboard API
      const textArea = document.createElement('textarea')
      textArea.value = configText
      document.body.appendChild(textArea)
      textArea.select()
      document.execCommand('copy')
      document.body.removeChild(textArea)
    })
  }

  async getUsers(): Promise<User[]> {
    const response = await fetch(`${this.apiUrl}/users`, {
      headers: this.getAuthHeaders(),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        this.showLoginPage()
        throw new Error('Authentication required')
      }
      throw new Error('Failed to fetch users')
    }
    
    return response.json()
  }

  async createUser(username: string, password: string, role: string): Promise<User> {
    const response = await fetch(`${this.apiUrl}/users`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ username, password, role }),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        this.showLoginPage()
        throw new Error('Authentication required')
      }
      const error = await response.json()
      throw new Error(error.error || 'Failed to create user')
    }
    
    return response.json()
  }

  async deleteUser(id: string): Promise<void> {
    const response = await fetch(`${this.apiUrl}/users/${id}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        this.showLoginPage()
        throw new Error('Authentication required')
      }
      const error = await response.json()
      throw new Error(error.error || 'Failed to delete user')
    }
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    const response = await fetch(`${this.apiUrl}/account/password`, {
      method: 'PUT',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    })
    
    if (!response.ok) {
      if (response.status === 401) {
        this.showLoginPage()
        throw new Error('Authentication required')
      }
      const error = await response.json()
      throw new Error(error.error || 'Failed to change password')
    }
  }

  renderUsers(users: User[]): void {
    const usersList = document.getElementById('users-list')!
    
    if (users.length === 0) {
      usersList.innerHTML = '<div class="empty-state">No users yet. Add one above.</div>'
      return
    }

    const getRoleBadge = (role: string) => {
      const badges = {
        'sys': '<span class="role-badge sys"><i class="fas fa-crown"></i> System Admin</span>',
        'admin': '<span class="role-badge admin"><i class="fas fa-user-shield"></i> Administrator</span>',
        'user': '<span class="role-badge user"><i class="fas fa-user"></i> User</span>'
      }
      return badges[role as keyof typeof badges] || `<span class="role-badge">${role}</span>`
    }

    usersList.innerHTML = `
      <div class="users-grid">
        ${users.map(user => `
          <div class="user-card">
            <div class="user-card-header">
              <div class="user-info">
                <div class="user-avatar">
                  <i class="fas fa-user"></i>
                </div>
                <div class="user-details">
                  <h4 class="user-name">${user.username}</h4>
                  ${getRoleBadge(user.role)}
                </div>
              </div>
              <div class="user-actions">
                ${user.role !== 'sys' ? `
                  <button class="delete-btn small" data-id="${user.id}" title="Delete User">
                    <i class="fas fa-trash"></i>
                  </button>
                ` : `
                  <span class="protected-badge" title="System admin cannot be deleted">
                    <i class="fas fa-shield-alt"></i>
                  </span>
                `}
              </div>
            </div>
            <div class="user-card-footer">
              <div class="user-meta">
                <i class="fas fa-calendar-alt"></i>
                Created ${new Date(user.created_at).toLocaleDateString()}
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    `

    usersList.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault()
        const id = (e.target as HTMLElement).closest('button')?.dataset.id!
        const user = users.find(u => u.id === id)
        if (user && confirm(`Are you sure you want to delete user "${user.username}"?`)) {
          try {
            await this.deleteUser(id)
            this.loadUsers()
          } catch (error) {
            console.error('Failed to delete user:', error)
          }
        }
      })
    })
  }

  async loadUsers(): Promise<void> {
    if (!this.checkAuth()) {
      this.showLoginPage()
      return
    }
    
    try {
      const users = await this.getUsers()
      this.renderUsers(users)
    } catch (error) {
      console.error('Failed to load users:', error)
      if (error instanceof Error && error.message === 'Authentication required') {
        this.showLoginPage()
      }
    }
  }

  copyAccessKey(key: string, element: HTMLElement): void {
    navigator.clipboard.writeText(key).then(() => {
      const notification = element.querySelector('.copy-notification') as HTMLElement
      if (notification) {
        notification.classList.add('show')
        
        setTimeout(() => {
          notification.classList.remove('show')
        }, 2000)
      }
    }).catch(() => {
      // Fallback for browsers that don't support clipboard API
      const textArea = document.createElement('textarea')
      textArea.value = key
      document.body.appendChild(textArea)
      textArea.select()
      document.execCommand('copy')
      document.body.removeChild(textArea)
      
      const notification = element.querySelector('.copy-notification') as HTMLElement
      if (notification) {
        notification.classList.add('show')
        
        setTimeout(() => {
          notification.classList.remove('show')
        }, 2000)
      }
    })
  }

  createLoginPage(): void {
    // Create a standalone login page that replaces the entire app
    const app = document.getElementById('app')!
    const loginPage = document.createElement('div')
    loginPage.id = 'login-page'
    loginPage.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: #f8f9fa;
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    `
    loginPage.innerHTML = `
      <div style="max-width: 400px; width: 90%; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border: 1px solid #e9ecef;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2c3e50; margin-bottom: 8px; font-size: 1.8rem; font-weight: 500;">Atlas Panel</h1>
        </div>
        <form id="login-form">
          <div style="margin-bottom: 20px;">
            <input type="text" id="login-username" placeholder="Username" required style="width: 100%; padding: 12px 16px; border: 1px solid #dee2e6; border-radius: 6px; font-size: 14px; box-sizing: border-box;">
          </div>
          <div style="margin-bottom: 30px;">
            <input type="password" id="login-password" placeholder="Password" required style="width: 100%; padding: 12px 16px; border: 1px solid #dee2e6; border-radius: 6px; font-size: 14px; box-sizing: border-box;">
          </div>
          <button type="submit" style="width: 100%; padding: 12px 20px; background: #3498db; color: white; border: none; border-radius: 6px; font-size: 14px; font-weight: 500; cursor: pointer;">Login</button>
          <div id="login-error" style="margin-top: 15px; padding: 10px; background: #f8d7da; color: #721c24; border-radius: 4px; display: none; font-size: 14px;"></div>
        </form>
      </div>
    `
    app.appendChild(loginPage)

    const loginForm = document.getElementById('login-form') as HTMLFormElement
    const usernameInput = document.getElementById('login-username') as HTMLInputElement
    const passwordInput = document.getElementById('login-password') as HTMLInputElement
    const errorDiv = document.getElementById('login-error') as HTMLElement

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault()
      errorDiv.style.display = 'none'
      
      try {
        await this.login(usernameInput.value, passwordInput.value)
        // Remove login page and show main app
        const loginPageElement = document.getElementById('login-page')
        if (loginPageElement) {
          loginPageElement.remove()
        }
        
        // Redirect to dashboard after login
        window.location.href = '/dashboard'
      } catch (error) {
        errorDiv.textContent = error instanceof Error ? error.message : 'Login failed'
        errorDiv.style.display = 'block'
      }
    })
  }

  updateSidebar(): void {
    const userInfo = document.querySelector('.sidebar-header')
    if (userInfo && this.currentUser) {
      userInfo.innerHTML = `
        <h1>Atlas Panel</h1>
        <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #34495e; font-size: 13px; color: #bdc3c7;">
          <div>Welcome, ${this.currentUser.username}</div>
          <div style="font-size: 11px; color: #95a5a6; margin-top: 2px;">Role: ${this.currentUser.role}</div>
          <button id="logout-btn" style="margin-top: 8px; padding: 4px 8px; background: #e74c3c; color: white; border: none; border-radius: 4px; font-size: 11px; cursor: pointer;">Logout</button>
        </div>
      `
      
      document.getElementById('logout-btn')?.addEventListener('click', async () => {
        await this.logout()
        window.location.href = '/'
      })
    }

    // Show/hide admin-only nav items and sections
    const isAdmin = this.currentUser?.role === 'admin' || this.currentUser?.role === 'sys'
    document.querySelectorAll('.nav-item[data-admin-only]').forEach(item => {
      (item as HTMLElement).style.display = isAdmin ? 'block' : 'none'
    })
    
    // Show/hide add node section for admins only
    const addNodeSection = document.getElementById('add-node-section')
    if (addNodeSection) {
      addNodeSection.style.display = isAdmin ? 'block' : 'none'
    }
    
  }

  openShell(nodeId: string, nodeName: string): void {
    if (!this.authToken) {
      this.showLoginPage()
      return
    }

    // Check if user has admin privileges
    if (this.currentUser?.role !== 'admin' && this.currentUser?.role !== 'sys') {
      alert('Shell access requires administrator privileges')
      return
    }

    // Close any existing terminal
    this.closeShell()

    // Create terminal container
    const terminalContainer = document.createElement('div')
    terminalContainer.className = 'terminal-container'
    terminalContainer.innerHTML = `
      <div class="terminal-modal">
        <div class="terminal-header">
          <div class="terminal-title">
            <i class="fas fa-terminal"></i>
            Shell: ${nodeName}
          </div>
          <div class="terminal-controls">
            <button class="terminal-btn reconnect" onclick="panel.reconnectShell()">
              <i class="fas fa-redo"></i> Reconnect
            </button>
            <button class="terminal-btn close" onclick="panel.closeShell()">
              <i class="fas fa-times"></i> Close
            </button>
          </div>
        </div>
        <div class="terminal-body">
          <div class="terminal-wrapper" id="terminal-wrapper"></div>
        </div>
      </div>
    `

    // Add to page
    document.body.appendChild(terminalContainer)

    // Initialize terminal
    const terminalWrapper = document.getElementById('terminal-wrapper')!
    
    if (this.useSimpleTerminal) {
      const terminalOptions: SimpleTerminalOptions = {
        nodeId,
        nodeName,
        apiUrl: this.apiUrl,
        authToken: this.authToken,
        onClose: () => this.closeShell(),
        onError: (error) => {
          console.error('Terminal error:', error)
          alert(`Terminal error: ${error}`)
        }
      }

      this.currentTerminal = new SimpleTerminal(terminalWrapper, terminalOptions)
    } else {
      const terminalOptions: TerminalOptions = {
        nodeId,
        nodeName,
        apiUrl: this.apiUrl,
        authToken: this.authToken,
        onClose: () => this.closeShell(),
        onError: (error) => {
          console.error('Terminal error:', error)
          alert(`Terminal error: ${error}`)
        }
      }

      this.currentTerminal = new NodeTerminal(terminalWrapper, terminalOptions)
    }
    
    this.currentTerminal.init()

    // Focus the terminal after initialization
    setTimeout(() => {
      this.currentTerminal?.focus()
    }, 200)

    // Handle ESC key to close terminal
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        this.closeShell()
        document.removeEventListener('keydown', handleEscape)
      }
    }
    document.addEventListener('keydown', handleEscape)

    // Handle click outside to close
    terminalContainer.addEventListener('click', (e) => {
      if (e.target === terminalContainer) {
        this.closeShell()
      }
    })
  }

  reconnectShell(): void {
    if (this.currentTerminal) {
      this.currentTerminal.reconnect()
    }
  }

  closeShell(): void {
    if (this.currentTerminal) {
      this.currentTerminal.dispose()
      this.currentTerminal = null
    }

    const terminalContainer = document.querySelector('.terminal-container')
    if (terminalContainer) {
      terminalContainer.remove()
    }
  }
}

const panel = new AtlasPanel()
panel.init()

// Make panel globally available for onclick handlers
;(window as any).panel = panel
