require "http/server"
require "socket"
require "json"
require "log"

Log.setup do |c|
  backend = Log::IOBackend.new
  backend.formatter = Log::Formatter.new do |entry, io|
    io << entry.timestamp.to_rfc3339 << " "
    io << entry.severity.to_s.rjust(7) << " | "
    io << "[#{entry.source}] "
    io << entry.message
  end
  c.bind("*", :debug, backend)
end

enum PacketType : UInt8
  CONNECT = 0x01
  DATA = 0x02
  CONTINUE = 0x03
  CLOSE = 0x04
end

enum StreamType : UInt8
  TCP = 0x01
  UDP = 0x02
end

enum CloseReason : UInt8
  UNSPECIFIED = 0x01
  VOLUNTARY = 0x02
  NETWORK_ERROR = 0x03
  INVALID_INFO = 0x41
  UNREACHABLE = 0x42
  TIMEOUT = 0x43
  REFUSED = 0x44
  TCP_TIMEOUT = 0x47
  BLOCKED = 0x48
  THROTTLED = 0x49
  CLIENT_ERROR = 0x81
end

class WispError < Exception
  property reason : CloseReason
  def initialize(@reason : CloseReason, message : String? = nil)
    Log.debug { "Creating WispError: #{@reason} - #{message}" }
    super(message || @reason.to_s)
  end
end

class WispPacket
  property type : PacketType
  property stream_id : UInt32
  property payload : Bytes

  def initialize(@type : PacketType, @stream_id : UInt32, @payload : Bytes)
    Log.debug { "Creating packet: type=#{@type}, stream_id=#{@stream_id}, payload_size=#{@payload.size}" }
  end

  def self.parse(data : Bytes) : WispPacket
    Log.debug { "Parsing packet data of size #{data.size} bytes" }
    type = PacketType.new(data[0])
    stream_id = IO::ByteFormat::LittleEndian.decode(UInt32, data[1, 4])
    payload = data[5..]
    Log.debug { "Parsed packet: type=#{type}, stream_id=#{stream_id}, payload_size=#{payload.size}" }
    WispPacket.new(type, stream_id, payload)
  end

  def to_bytes : Bytes
    Log.debug { "Converting packet to bytes: type=#{@type}, stream_id=#{@stream_id}" }
    io = IO::Memory.new
    io.write_byte(@type.value)
    io.write_bytes(@stream_id, IO::ByteFormat::LittleEndian)
    io.write(@payload)
    io.to_slice
  end
end

class Connection
  property socket : HTTP::WebSocket
  property stream : TCPSocket | UDPSocket | Nil
  property buffer : Int32
  property buffer_queue : Array(Bytes)
  property stream_type : StreamType
  property connected : Bool
  property hostname : String
  property port : Int32
  property last_continue : Time
  property closing : Bool = false

  def initialize(@socket, @hostname = "", @port = 0, @stream_type = StreamType::TCP)
    Log.debug { "Initializing new connection: host=#{@hostname}, port=#{@port}, type=#{@stream_type}" }
    @buffer = 127
    @buffer_queue = [] of Bytes
    @connected = false
    @last_continue = Time.utc
  end

  def cleanup
    Log.debug { "Cleaning up connection: host=#{@hostname}, port=#{@port}" }
    return unless @stream
    case @stream
    when TCPSocket
      Log.debug { "Closing TCP socket" }
      @stream.as(TCPSocket).close rescue nil
    when UDPSocket
      Log.debug { "Closing UDP socket" }
      @stream.as(UDPSocket).close rescue nil
    end
    @connected = false
  end
end

class WispServer
  INITIAL_BUFFER_SIZE = 127
  CONTINUE_INTERVAL = 5.seconds
  BUFFER_THRESHOLD = INITIAL_BUFFER_SIZE // 2

  def initialize(@port : Int32 = 3000, @path : String = "/wisp/")
    Log.info { "Initializing WispServer on port #{@port} with path #{@path}" }
    raise "Wisp endpoints must end with a trailing forward slash" unless @path.ends_with?("/")
    @connections = {} of UInt32 => Connection
  end

  def start
    Log.info { "Starting WispServer..." }
    handlers = [HTTP::WebSocketHandler.new do |ws, ctx|
      Log.debug { "New WebSocket connection attempt from #{ctx.request.remote_address}" }
      if ctx.request.path == @path
        handle_websocket(ws)
      else
        Log.warn { "Invalid path requested: #{ctx.request.path}" }
        ws.close(4004, "Invalid path")
      end
    end]

    server = HTTP::Server.new(handlers)
    address = server.bind_tcp("0.0.0.0", @port)
    Log.info { "Server listening on http://#{address}" }
    server.listen
  end

  private def handle_websocket(socket : HTTP::WebSocket)
    Log.debug { "Setting up new WebSocket connection" }
    send_continue_packet(socket, 0_u32, INITIAL_BUFFER_SIZE)
    
    socket.on_binary do |message|
      Log.debug { "Received binary message of size #{message.size} bytes" }
      handle_message(socket, message)
    end

    socket.on_close do
      Log.debug { "WebSocket connection closing" }
      cleanup_all_connections(socket)
    end

    socket.on_ping do |data|
      Log.debug { "Received ping, responding with pong" }
      socket.pong(data)
    end
  end

  private def handle_message(socket : HTTP::WebSocket, message : Bytes)
    packet = WispPacket.parse(message)
    Log.debug { "Processing packet: type=#{packet.type}, stream_id=#{packet.stream_id}" }
    
    case packet.type
    when PacketType::CONNECT
      Log.debug { "Handling CONNECT packet" }
      handle_connect(socket, packet)
    when PacketType::DATA
      Log.debug { "Handling DATA packet" }
      handle_data(socket, packet)
    when PacketType::CLOSE
      Log.debug { "Handling CLOSE packet" }
      handle_close(socket, packet)
    end
  end

  private def validate_stream_type(type : UInt8)
    Log.debug { "Validating stream type: #{type}" }
    raise WispError.new(CloseReason::INVALID_INFO) unless type == StreamType::TCP.value || type == StreamType::UDP.value
  end

  private def validate_connection_request(hostname : String, port : Int32)
    Log.debug { "Validating connection request: #{hostname}:#{port}" }
    raise WispError.new(CloseReason::INVALID_INFO) if port <= 0 || port > 65535
  end

  private def handle_connect(socket : HTTP::WebSocket, packet : WispPacket)
    Log.debug { "Processing connect request for stream #{packet.stream_id}" }
    stream_type = packet.payload[0]
    validate_stream_type(stream_type)
    port = IO::ByteFormat::LittleEndian.decode(UInt16, packet.payload[1, 2])
    hostname = String.new(packet.payload[3..])
    
    Log.debug { "Connection details - Type: #{stream_type}, Host: #{hostname}, Port: #{port}" }
    validate_connection_request(hostname, port)

    connection = Connection.new(
      socket: socket,
      hostname: hostname,
      port: port,
      stream_type: StreamType.new(stream_type)
    )
    
    @connections[packet.stream_id] = connection
    setup_stream(packet.stream_id, connection)
  rescue ex
    Log.error { "Connect error: #{ex.message}" }
    handle_error(socket, packet.stream_id, ex)
  end

  private def setup_stream(stream_id : UInt32, connection : Connection)
    Log.debug { "Setting up stream #{stream_id} of type #{connection.stream_type}" }
    case connection.stream_type
    when StreamType::TCP then setup_tcp_stream(stream_id, connection)
    when StreamType::UDP then setup_udp_stream(stream_id, connection)
    end
  rescue ex
    Log.error { "Stream setup error: #{ex.message}" }
    handle_error(connection.socket, stream_id, ex)
  end

  private def setup_tcp_stream(stream_id : UInt32, connection : Connection)
    Log.debug { "Setting up TCP stream to #{connection.hostname}:#{connection.port}" }
    tcp_socket = TCPSocket.new(connection.hostname, connection.port, connect_timeout: 10.seconds)
    connection.stream = tcp_socket
    connection.connected = true
    send_continue_packet(connection.socket, stream_id, INITIAL_BUFFER_SIZE)
    spawn handle_tcp_read(stream_id, connection, tcp_socket)
  end

  private def setup_udp_stream(stream_id : UInt32, connection : Connection)
    Log.debug { "Setting up UDP stream to #{connection.hostname}:#{connection.port}" }
    udp_socket = UDPSocket.new(connection.hostname.includes?(":") ? Socket::Family::INET6 : Socket::Family::INET)
    udp_socket.connect(connection.hostname, connection.port)
    connection.stream = udp_socket
    connection.connected = true
    spawn handle_udp_read(stream_id, connection, udp_socket)
  end

  private def handle_tcp_read(stream_id : UInt32, connection : Connection, tcp_socket : TCPSocket)
    Log.debug { "Starting TCP read loop for stream #{stream_id}" }
    buffer = Bytes.new(4096)
    loop do
      begin
        bytes_read = tcp_socket.read(buffer)
        Log.debug { "TCP read #{bytes_read} bytes from stream #{stream_id}" }
        break if bytes_read <= 0
        send_data_packet(connection.socket, stream_id, buffer[0, bytes_read])
      rescue ex : IO::Error
        Log.error { "TCP read error: #{ex.message}" }
        break
      end
    end
  rescue ex : IO::TimeoutError
    Log.error { "TCP timeout on stream #{stream_id}" }
    handle_error(connection.socket, stream_id, WispError.new(CloseReason::TCP_TIMEOUT))
  rescue ex : Socket::Error
    Log.error { "TCP error on stream #{stream_id}: #{ex.message}" }
    handle_error(connection.socket, stream_id, WispError.new(CloseReason::NETWORK_ERROR))
  ensure
    Log.debug { "Cleaning up TCP stream #{stream_id}" }
    connection.closing = true
    cleanup_stream(stream_id)
    send_close_packet(connection.socket, stream_id, CloseReason::VOLUNTARY.value)
  end

  private def handle_udp_read(stream_id : UInt32, connection : Connection, udp_socket : UDPSocket)
    Log.debug { "Starting UDP read loop for stream #{stream_id}" }
    buffer = Bytes.new(4096)
    while (bytes_read = udp_socket.read(buffer)) > 0
      Log.debug { "UDP read #{bytes_read} bytes from stream #{stream_id}" }
      send_data_packet(connection.socket, stream_id, buffer[0, bytes_read])
    end
  rescue ex : Socket::Error
    Log.error { "UDP error on stream #{stream_id}: #{ex.message}" }
    handle_error(connection.socket, stream_id, WispError.new(CloseReason::NETWORK_ERROR))
  ensure
    Log.debug { "Cleaning up UDP stream #{stream_id}" }
    cleanup_stream(stream_id)
  end

  private def handle_data(socket : HTTP::WebSocket, packet : WispPacket)
    Log.debug { "Handling data packet for stream #{packet.stream_id}" }
    return unless connection = @connections[packet.stream_id]?
    return unless stream = connection.stream
    return if connection.closing

    case connection.stream_type
    when StreamType::TCP then handle_tcp_data(connection, packet)
    when StreamType::UDP then handle_udp_data(connection, packet)
    end
  rescue ex
    Log.error { "Data handling error: #{ex.message}" }
    handle_error(socket, packet.stream_id, WispError.new(CloseReason::NETWORK_ERROR))
  end

  private def handle_tcp_data(connection : Connection, packet : WispPacket)
    Log.debug { "Writing #{packet.payload.size} bytes to TCP stream" }
    return unless stream = connection.stream.as?(TCPSocket)
    stream.write(packet.payload)
    stream.flush
    check_continue_needed(connection, packet.stream_id)
  end

  private def handle_udp_data(connection : Connection, packet : WispPacket)
    Log.debug { "Sending #{packet.payload.size} bytes via UDP" }
    return unless stream = connection.stream.as?(UDPSocket)
    stream.send(packet.payload)
  end

  private def check_continue_needed(connection : Connection, stream_id : UInt32)
    now = Time.utc
    if connection.buffer <= BUFFER_THRESHOLD || (now - connection.last_continue) >= CONTINUE_INTERVAL
      Log.debug { "Sending continue packet for stream #{stream_id}" }
      connection.buffer = INITIAL_BUFFER_SIZE
      connection.last_continue = now
      send_continue_packet(connection.socket, stream_id, connection.buffer)
    end
  end

  private def handle_close(socket : HTTP::WebSocket, packet : WispPacket)
    Log.debug { "Processing close request for stream #{packet.stream_id}" }
    if connection = @connections[packet.stream_id]?
      connection.cleanup
      @connections.delete(packet.stream_id)
    end
  end

  private def handle_error(socket : HTTP::WebSocket, stream_id : UInt32, error : Exception)
    Log.error { "Handling error for stream #{stream_id}: #{error.message}" }
    return unless connection = @connections[stream_id]?
    return if connection.closing

    reason = case error
    when Socket::ConnectError   then CloseReason::REFUSED
    when Socket::TimeoutError   then CloseReason::TIMEOUT
    when Socket::Error         then CloseReason::NETWORK_ERROR
    when WispError            then error.reason
    when Socket::Addrinfo::Error then CloseReason::UNREACHABLE
    else                      CloseReason::UNSPECIFIED
    end

    connection.closing = true
    send_close_packet(socket, stream_id, reason.value)
    cleanup_stream(stream_id)
  end

  private def send_data_packet(socket : HTTP::WebSocket, stream_id : UInt32, data : Bytes)
    Log.debug { "Sending data packet: stream_id=#{stream_id}, size=#{data.size}" }
    return if socket.closed?
    packet = WispPacket.new(PacketType::DATA, stream_id, data)
    socket.send(packet.to_bytes)
  rescue IO::Error
    Log.error { "Failed to send data packet" }
  end

  private def send_continue_packet(socket : HTTP::WebSocket, stream_id : UInt32, buffer_size : Int32)
    Log.debug { "Sending continue packet: stream_id=#{stream_id}, buffer_size=#{buffer_size}" }
    return if socket.closed?
    payload = IO::Memory.new
    payload.write_bytes(buffer_size.to_u32, IO::ByteFormat::LittleEndian)
    packet = WispPacket.new(PacketType::CONTINUE, stream_id, payload.to_slice)
    socket.send(packet.to_bytes)
  rescue IO::Error
    Log.error { "Failed to send continue packet" }
  end

  private def send_close_packet(socket : HTTP::WebSocket, stream_id : UInt32, reason : UInt8)
    Log.debug { "Sending close packet: stream_id=#{stream_id}, reason=#{reason}" }
    return if socket.closed?
    packet = WispPacket.new(PacketType::CLOSE, stream_id, Bytes[reason])
    socket.send(packet.to_bytes)
  rescue IO::Error
    Log.error { "Failed to send close packet" }
  end

  private def cleanup_stream(stream_id : UInt32)
    Log.debug { "Cleaning up stream #{stream_id}" }
    if connection = @connections[stream_id]?
      connection.cleanup
      @connections.delete(stream_id)
    end
  end

  private def cleanup_all_connections(socket : HTTP::WebSocket)
    Log.debug { "Cleaning up all connections for WebSocket" }
    @connections.each do |stream_id, connection|
      if connection.socket == socket
        cleanup_stream(stream_id)
      end
    end
  end
end

server = WispServer.new(6001)
server.start
