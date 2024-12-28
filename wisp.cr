require "http/server"
require "socket"
require "json"
require "log"

Log.setup do |c|
  backend = Log::IOBackend.new
  backend.formatter = Log::Formatter.new do |entry, io|
    io << entry.timestamp.to_rfc3339 << " "
    io << entry.severity.to_s.rjust(5) << " | "
    io << entry.message
  end
  c.bind("*", :info, backend)
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
    super(message || @reason.to_s)
  end
end

class WispPacket
  property type : PacketType
  property stream_id : UInt32
  property payload : Bytes

  def initialize(@type : PacketType, @stream_id : UInt32, @payload : Bytes)
  end

  def self.parse(data : Bytes) : WispPacket
    type = PacketType.new(data[0])
    stream_id = IO::ByteFormat::LittleEndian.decode(UInt32, data[1, 4])
    payload = data[5..]
    WispPacket.new(type, stream_id, payload)
  end

  def to_bytes : Bytes
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

  def initialize(@socket, @hostname = "", @port = 0, @stream_type = StreamType::TCP)
    @buffer = 127
    @buffer_queue = [] of Bytes
    @connected = false
    @last_continue = Time.utc
  end

  def cleanup
    return unless @stream
    case @stream
    when TCPSocket then @stream.as(TCPSocket).close rescue nil
    when UDPSocket then @stream.as(UDPSocket).close rescue nil
    end
    @connected = false
  end
end

class WispServer
  INITIAL_BUFFER_SIZE = 127
  CONTINUE_INTERVAL = 5.seconds
  BUFFER_THRESHOLD = INITIAL_BUFFER_SIZE // 2

  def initialize(@port : Int32 = 3000, @path : String = "/wisp/")
    raise "Wisp endpoints must end with a trailing forward slash" unless @path.ends_with?("/")
    @connections = {} of UInt32 => Connection
  end

  def start
    handlers = [HTTP::WebSocketHandler.new do |ws, ctx|
      if ctx.request.path == @path
        handle_websocket(ws)
      else
        ws.close(4004, "Invalid path")
      end
    end]

    server = HTTP::Server.new(handlers)
    address = server.bind_tcp("0.0.0.0", @port)
    Log.info { "Server listening on http://#{address}" }
    server.listen
  end

  private def handle_websocket(socket : HTTP::WebSocket)
    send_continue_packet(socket, 0_u32, INITIAL_BUFFER_SIZE)

    socket.on_binary do |message|
      handle_message(socket, message)
    end

    socket.on_close do
      cleanup_all_connections(socket)
    end

    socket.on_ping { |data| socket.pong(data) }
  end

  private def handle_message(socket : HTTP::WebSocket, message : Bytes)
    packet = WispPacket.parse(message)
    case packet.type
    when PacketType::CONNECT then handle_connect(socket, packet)
    when PacketType::DATA then handle_data(socket, packet)
    when PacketType::CLOSE then handle_close(socket, packet)
    end
  end

  private def validate_stream_type(type : UInt8)
    raise WispError.new(CloseReason::INVALID_INFO) unless type == StreamType::TCP.value || type == StreamType::UDP.value
  end

  private def validate_connection_request(hostname : String, port : Int32)
    raise WispError.new(CloseReason::INVALID_INFO) if port <= 0 || port > 65535
    if hostname.matches?(/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/) || hostname.matches?(/^(127\.|0\.0\.0\.0)/)
      raise WispError.new(CloseReason::BLOCKED)
    end
  end

  private def handle_connect(socket : HTTP::WebSocket, packet : WispPacket)
    stream_type = packet.payload[0]
    validate_stream_type(stream_type)
    port = IO::ByteFormat::LittleEndian.decode(UInt16, packet.payload[1, 2])
    hostname = String.new(packet.payload[3..])
    
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
    case connection.stream_type
    when StreamType::TCP then setup_tcp_stream(stream_id, connection)
    when StreamType::UDP then setup_udp_stream(stream_id, connection)
    end
  rescue ex
    handle_error(connection.socket, stream_id, ex)
  end

  private def setup_tcp_stream(stream_id : UInt32, connection : Connection)
    tcp_socket = TCPSocket.new(connection.hostname, connection.port, connect_timeout: 10.seconds)
    connection.stream = tcp_socket
    connection.connected = true
    send_continue_packet(connection.socket, stream_id, INITIAL_BUFFER_SIZE)
    spawn handle_tcp_read(stream_id, connection, tcp_socket)
  end

  private def setup_udp_stream(stream_id : UInt32, connection : Connection)
    udp_socket = UDPSocket.new(connection.hostname.includes?(":") ? Socket::Family::INET6 : Socket::Family::INET)
    udp_socket.connect(connection.hostname, connection.port)
    connection.stream = udp_socket
    connection.connected = true
    spawn handle_udp_read(stream_id, connection, udp_socket)
  end

  private def handle_tcp_read(stream_id : UInt32, connection : Connection, tcp_socket : TCPSocket)
    buffer = Bytes.new(4096)
    loop do
      begin
        bytes_read = tcp_socket.read(buffer)
        break if bytes_read <= 0
        send_data_packet(connection.socket, stream_id, buffer[0, bytes_read])
      rescue ex : IO::Error
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
    cleanup_stream(stream_id)
    begin
      send_close_packet(connection.socket, stream_id, CloseReason::VOLUNTARY.value)
    rescue
    end
  end

  private def handle_udp_read(stream_id : UInt32, connection : Connection, udp_socket : UDPSocket)
    buffer = Bytes.new(4096)
    while (bytes_read = udp_socket.read(buffer)) > 0
      send_data_packet(connection.socket, stream_id, buffer[0, bytes_read])
    end
  rescue ex : Socket::Error
    handle_error(connection.socket, stream_id, WispError.new(CloseReason::NETWORK_ERROR))
  ensure
    cleanup_stream(stream_id)
  end

  private def handle_data(socket : HTTP::WebSocket, packet : WispPacket)
    return unless connection = @connections[packet.stream_id]?
    return unless stream = connection.stream

    case connection.stream_type
    when StreamType::TCP then handle_tcp_data(connection, packet)
    when StreamType::UDP then handle_udp_data(connection, packet)
    end
  rescue ex
    handle_error(socket, packet.stream_id, WispError.new(CloseReason::NETWORK_ERROR))
  end

  private def handle_tcp_data(connection : Connection, packet : WispPacket)
    return unless stream = connection.stream.as?(TCPSocket)
    stream.write(packet.payload)
    stream.flush
    check_continue_needed(connection, packet.stream_id)
  end

  private def handle_udp_data(connection : Connection, packet : WispPacket)
    return unless stream = connection.stream.as?(UDPSocket)
    stream.send(packet.payload)
  end

  private def check_continue_needed(connection : Connection, stream_id : UInt32)
    now = Time.utc
    if connection.buffer <= BUFFER_THRESHOLD || (now - connection.last_continue) >= CONTINUE_INTERVAL
      connection.buffer = INITIAL_BUFFER_SIZE
      connection.last_continue = now
      send_continue_packet(connection.socket, stream_id, connection.buffer)
    end
  end

  private def handle_close(socket : HTTP::WebSocket, packet : WispPacket)
    if connection = @connections[packet.stream_id]?
      connection.cleanup
      @connections.delete(packet.stream_id)
    end
  end

  private def handle_error(socket : HTTP::WebSocket, stream_id : UInt32, error : Exception)
    reason = case error
    when Socket::ConnectError   then CloseReason::REFUSED
    when Socket::TimeoutError   then CloseReason::TIMEOUT
    when Socket::Error         then CloseReason::NETWORK_ERROR
    when WispError            then error.reason
    when Socket::Addrinfo::Error then CloseReason::UNREACHABLE
    else                      CloseReason::UNSPECIFIED
    end

    Log.error { "Stream #{stream_id} error: #{error.message}" }
    send_close_packet(socket, stream_id, reason.value)
    cleanup_stream(stream_id)
  end

  private def send_data_packet(socket : HTTP::WebSocket, stream_id : UInt32, data : Bytes)
    return if socket.closed?
    packet = WispPacket.new(PacketType::DATA, stream_id, data)
    socket.send(packet.to_bytes)
  rescue IO::Error
  end
  
  private def send_continue_packet(socket : HTTP::WebSocket, stream_id : UInt32, buffer_size : Int32)
    return if socket.closed?
    payload = IO::Memory.new
    payload.write_bytes(buffer_size.to_u32, IO::ByteFormat::LittleEndian)
    packet = WispPacket.new(PacketType::CONTINUE, stream_id, payload.to_slice)
    socket.send(packet.to_bytes)
  rescue IO::Error
  end
  
  private def send_close_packet(socket : HTTP::WebSocket, stream_id : UInt32, reason : UInt8)
    return if socket.closed?
    packet = WispPacket.new(PacketType::CLOSE, stream_id, Bytes[reason])
    socket.send(packet.to_bytes)
  rescue IO::Error
  end
  

  private def cleanup_stream(stream_id : UInt32)
    if connection = @connections[stream_id]?
      connection.cleanup
      @connections.delete(stream_id)
    end
  end

  private def cleanup_all_connections(socket : HTTP::WebSocket)
    @connections.each do |stream_id, connection|
      if connection.socket == socket
        cleanup_stream(stream_id)
      end
    end
  end
end

server = WispServer.new(3001)
server.start
