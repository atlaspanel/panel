import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'

export interface TerminalOptions {
  nodeId: string
  nodeName: string
  apiUrl: string
  authToken: string
  onClose?: () => void
  onError?: (error: string) => void
}

export class NodeTerminal {
  private terminal: Terminal
  private fitAddon: FitAddon
  private websocket: WebSocket | null = null
  private container: HTMLElement
  private options: TerminalOptions
  private reconnectAttempts = 0
  private maxReconnectAttempts = 3
  private reconnectTimeout: number | null = null

  constructor(container: HTMLElement, options: TerminalOptions) {
    this.container = container
    this.options = options
    
    // Create terminal with simpler, more reliable configuration
    this.terminal = new Terminal({
      cursorBlink: true,
      theme: {
        background: '#1e1e1e',
        foreground: '#ffffff',
        cursor: '#ffffff',
        selectionBackground: '#666666'
      },
      fontSize: 13,
      fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace',
      allowProposedApi: true
    })

    this.fitAddon = new FitAddon()
    this.terminal.loadAddon(this.fitAddon)
  }

  public init(): void {
    // Ensure container has explicit dimensions
    this.container.style.width = '100%'
    this.container.style.height = '100%'
    
    // Open terminal in container
    this.terminal.open(this.container)
    
    // Wait for container to be properly sized, then fit terminal
    const initResize = () => {
      if (this.container.offsetWidth > 0 && this.container.offsetHeight > 0) {
        this.fitAddon.fit()
        this.terminal.focus()
      } else {
        setTimeout(initResize, 50)
      }
    }
    
    setTimeout(initResize, 100)

    // Set up terminal input handling
    this.terminal.onData((data) => {
      if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
        this.websocket.send(data)
      }
    })

    // Handle window resize with debouncing
    let resizeTimeout: number | null = null
    const handleResize = () => {
      if (resizeTimeout) {
        clearTimeout(resizeTimeout)
      }
      resizeTimeout = window.setTimeout(() => {
        this.fitAddon.fit()
      }, 150)
    }
    
    window.addEventListener('resize', handleResize)

    // Connect to shell
    this.connect()
  }

  private connect(): void {
    this.terminal.writeln('\r\n\x1b[1;34mConnecting to node shell...\x1b[0m\r\n')

    // Determine WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = this.options.apiUrl.replace(/^https?:\/\//, '')
    const wsUrl = `${protocol}//${host}/nodes/${this.options.nodeId}/shell?token=${encodeURIComponent(this.options.authToken)}`

    try {
      this.websocket = new WebSocket(wsUrl)
      
      this.websocket.onopen = () => {
        this.terminal.writeln('\x1b[1;32mConnected to shell!\x1b[0m\r\n')
        this.reconnectAttempts = 0
      }

      this.websocket.onmessage = (event) => {
        // Handle both text and binary messages
        if (typeof event.data === 'string') {
          this.terminal.write(event.data)
        } else if (event.data instanceof Blob) {
          // Convert binary data to text
          event.data.text().then((text) => {
            this.terminal.write(text)
          })
        }
      }

      this.websocket.onclose = (event) => {
        if (event.wasClean) {
          this.terminal.writeln('\r\n\x1b[1;33mConnection closed cleanly.\x1b[0m')
        } else {
          this.terminal.writeln('\r\n\x1b[1;31mConnection lost unexpectedly.\x1b[0m')
          this.attemptReconnect()
        }
      }

      this.websocket.onerror = (error) => {
        console.error('WebSocket error:', error)
        this.terminal.writeln('\r\n\x1b[1;31mConnection error occurred.\x1b[0m')
        if (this.options.onError) {
          this.options.onError('WebSocket connection failed')
        }
      }

    } catch (error) {
      console.error('Failed to create WebSocket:', error)
      this.terminal.writeln('\r\n\x1b[1;31mFailed to create connection.\x1b[0m')
      if (this.options.onError) {
        this.options.onError('Failed to create WebSocket connection')
      }
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++
      this.terminal.writeln(`\r\n\x1b[1;33mReconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})\x1b[0m`)
      
      this.reconnectTimeout = window.setTimeout(() => {
        this.connect()
      }, 2000 * this.reconnectAttempts) // Exponential backoff
    } else {
      this.terminal.writeln('\r\n\x1b[1;31mFailed to reconnect after multiple attempts.\x1b[0m')
      if (this.options.onError) {
        this.options.onError('Failed to reconnect to shell')
      }
    }
  }

  public reconnect(): void {
    this.reconnectAttempts = 0
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
    this.disconnect()
    this.connect()
  }

  public disconnect(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
    
    if (this.websocket) {
      this.websocket.close()
      this.websocket = null
    }
  }

  public resize(): void {
    this.fitAddon.fit()
  }

  public dispose(): void {
    this.disconnect()
    this.terminal.dispose()
  }

  public focus(): void {
    this.terminal.focus()
  }

  public clear(): void {
    this.terminal.clear()
  }
}