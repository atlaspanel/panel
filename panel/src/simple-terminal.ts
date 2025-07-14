export interface SimpleTerminalOptions {
  nodeId: string
  nodeName: string
  apiUrl: string
  authToken: string
  onClose?: () => void
  onError?: (error: string) => void
}

export class SimpleTerminal {
  private container: HTMLElement
  private options: SimpleTerminalOptions
  private websocket: WebSocket | null = null
  private outputDiv!: HTMLElement
  private inputDiv!: HTMLElement
  private commandHistory: string[] = []
  private historyIndex = -1
  private currentLine = ''
  private reconnectAttempts = 0
  private maxReconnectAttempts = 3

  constructor(container: HTMLElement, options: SimpleTerminalOptions) {
    this.container = container
    this.options = options
    
    this.createTerminalElements()
  }

  private createTerminalElements(): void {
    this.container.innerHTML = `
      <div class="simple-terminal">
        <div class="terminal-output" id="terminal-output"></div>
        <div class="terminal-input-line">
          <span class="terminal-prompt">$ </span>
          <input type="text" class="terminal-input" id="terminal-input" autocomplete="off" spellcheck="false">
        </div>
      </div>
    `

    this.outputDiv = this.container.querySelector('#terminal-output')!
    this.inputDiv = this.container.querySelector('#terminal-input')! as HTMLInputElement

    this.setupInputHandling()
  }

  private setupInputHandling(): void {
    const input = this.inputDiv as HTMLInputElement

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault()
        this.handleCommand(input.value)
        input.value = ''
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        this.navigateHistory(-1)
        input.value = this.currentLine
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        this.navigateHistory(1)
        input.value = this.currentLine
      }
    })

    input.addEventListener('input', () => {
      this.currentLine = input.value
    })
  }

  private navigateHistory(direction: number): void {
    if (this.commandHistory.length === 0) return

    this.historyIndex += direction
    this.historyIndex = Math.max(-1, Math.min(this.commandHistory.length - 1, this.historyIndex))

    if (this.historyIndex === -1) {
      this.currentLine = ''
    } else {
      this.currentLine = this.commandHistory[this.historyIndex]
    }
  }

  private handleCommand(command: string): void {
    if (command.trim()) {
      this.commandHistory.unshift(command)
      this.historyIndex = -1
      
      // Add command to output
      this.addOutput(`$ ${command}`, 'command')
      
      // Send to WebSocket
      if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
        this.websocket.send(command + '\n')
      }
    } else if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
      this.websocket.send('\n')
    }
  }

  private addOutput(text: string, className: string = 'output'): void {
    const line = document.createElement('div')
    line.className = `terminal-line ${className}`
    line.textContent = text
    this.outputDiv.appendChild(line)
    
    // Auto-scroll to bottom
    this.outputDiv.scrollTop = this.outputDiv.scrollHeight
  }

  public init(): void {
    this.addOutput('Connecting to node shell...', 'info')
    this.connect()
    
    // Focus input
    setTimeout(() => {
      (this.inputDiv as HTMLInputElement).focus()
    }, 100)
  }

  private connect(): void {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = this.options.apiUrl.replace(/^https?:\/\//, '')
    const wsUrl = `${protocol}//${host}/nodes/${this.options.nodeId}/shell?token=${encodeURIComponent(this.options.authToken)}`

    try {
      this.websocket = new WebSocket(wsUrl)
      
      this.websocket.onopen = () => {
        this.addOutput('Connected to shell!', 'success')
        this.reconnectAttempts = 0
      }

      this.websocket.onmessage = (event) => {
        this.addOutput(event.data, 'output')
      }

      this.websocket.onclose = (event) => {
        if (event.wasClean) {
          this.addOutput('Connection closed cleanly.', 'info')
        } else {
          this.addOutput('Connection lost unexpectedly.', 'error')
          this.attemptReconnect()
        }
      }

      this.websocket.onerror = (error) => {
        console.error('WebSocket error:', error)
        this.addOutput('Connection error occurred.', 'error')
        if (this.options.onError) {
          this.options.onError('WebSocket connection failed')
        }
      }

    } catch (error) {
      console.error('Failed to create WebSocket:', error)
      this.addOutput('Failed to create connection.', 'error')
      if (this.options.onError) {
        this.options.onError('Failed to create WebSocket connection')
      }
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++
      this.addOutput(`Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`, 'info')
      
      setTimeout(() => {
        this.connect()
      }, 2000 * this.reconnectAttempts)
    } else {
      this.addOutput('Failed to reconnect after multiple attempts.', 'error')
      if (this.options.onError) {
        this.options.onError('Failed to reconnect to shell')
      }
    }
  }

  public reconnect(): void {
    this.reconnectAttempts = 0
    this.disconnect()
    this.connect()
  }

  public disconnect(): void {
    if (this.websocket) {
      this.websocket.close()
      this.websocket = null
    }
  }

  public focus(): void {
    (this.inputDiv as HTMLInputElement).focus()
  }

  public clear(): void {
    this.outputDiv.innerHTML = ''
  }

  public dispose(): void {
    this.disconnect()
  }
}