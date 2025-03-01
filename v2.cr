#AI generated V2 version with claude 3.7, apparently works better then origonal which was mostly made with 3.5, Cool! 

require "http/server"
require "socket"
require "socket/udp_socket"
require "socket/tcp_socket"
require "http/web_socket"
require "logger"

# Wisp Protocol Server Implementation in Crystal
# Based on Wisp Protocol v1.2 by @ading2210
class WispServer
  VERSION = "1.0.0"
  LOG_LEVEL = Logger::INFO

  # Packet types as defined in the Wisp spec
  enum PacketType : UInt8
    CONNECT  = 0x01
    DATA     = 0x02
    CONTINUE = 0x03
    CLOSE    = 0x04
  end

  # Stream types as defined in the Wisp spec
  enum StreamType : UInt8
    TCP = 0x01
    UDP = 0x02
  end

  # Close reasons as defined in the Wisp spec
  enum CloseReason : UInt8
    # Generic reasons (both client and server)
    UNSPECIFIED    = 0x01
    VOLUNTARY      = 0x02
    NETWORK_ERROR  = 0x03

    # Server-specific reasons
    INVALID_INFO        = 0x41
    UNREACHABLE_HOST    = 0x42
    CONNECTION_TIMEOUT  = 0x43
    CONNECTION_REFUSED  = 0x44
    TCP_TIMEOUT         = 0x47
    BLOCKED_ADDRESS     = 0x48
    THROTTLED           = 0x49

    # Client-specific reasons
    CLIENT_ERROR = 0x81
  end

  # Class to manage an individual stream connection
  class Stream
    property socket : TCPSocket | UDPSocket | Nil
    property stream_id : UInt32
    property host : String
    property port : UInt16
    property stream_type : StreamType
    property buffer : Array(Bytes)
    property is_open : Bool
    property buffer_remaining : UInt32

    def initialize(@stream_id : UInt32, @host : String, @port : UInt16, @stream_type : StreamType)
      @socket = nil
      @buffer = [] of Bytes
      @is_open = true
      @buffer_remaining = 0
    end

    # Close the stream's socket if it exists
    def close_socket
      if socket = @socket
        begin
          socket.close
        rescue
          # Ignore close errors
        end
        @socket = nil
      end
      @is_open = false
    end
  end

  getter logger : Logger
  getter streams : Hash(UInt32, Stream)
  getter max_buffer_size : UInt32
  getter connect_timeout : Float64

  def initialize(
    @host : String = "127.0.0.1",
    @port : Int32 = 6001,
    @path : String = "/",
    @max_buffer_size : UInt32 = 10_u32,
    @connect_timeout : Float64 = 10.0
  )
    @streams = {} of UInt32 => Stream
    @logger = Logger.new(STDOUT)
    @logger.level = LOG_LEVEL
  end

  # Start the HTTP server
  def start
    @logger.info("Starting Wisp server on #{@host}:#{@port}#{@path}")

    server = HTTP::Server.new do |context|
      if context.request.path == @path
        # Upgrade to WebSocket if the path matches
        if websocket_upgrade?(context)
          @logger.info("WebSocket connection established")
          handle_websocket(context)
        else
          # Return 426 if WebSocket upgrade is required
          context.response.status_code = 426
          context.response.content_type = "text/plain"
          context.response.print "Upgrade to WebSocket required"
        end
      else
        # Return 404 for all other paths
        context.response.status_code = 404
        context.response.content_type = "text/plain"
        context.response.print "Not Found"
      end
    end

    # Start the server
    server.bind_tcp(@host, @port)
    server.listen

    # Keep the main thread alive
    loop do
      sleep 1
    end
  end

  private def websocket_upgrade?(context) : Bool
    # Check if this is a WebSocket upgrade request
    return context.request.headers["Upgrade"]?.try(&.downcase) == "websocket"
  end

  private def handle_websocket(context)
    # Proper way to upgrade a connection to WebSocket
    HTTP::WebSocketHandler.new do |ws, _|
      # Send initial CONTINUE packet with buffer size
      send_continue(ws, 0_u32, @max_buffer_size)

      # Handle WebSocket messages
      ws.on_binary do |message|
        handle_packet(ws, message)
      end

      # Handle WebSocket close
      ws.on_close do
        # Clean up all streams for this WebSocket
        @streams.each_value do |stream|
          stream.close_socket
        end
        @streams.clear
        @logger.info("WebSocket connection closed")
      end
    end.call(context)
  end

  # Parse and handle an incoming packet
  private def handle_packet(ws : HTTP::WebSocket, data : Bytes)
    # Check if packet is too small
    if data.size < 5
      @logger.warn("Received packet is too small (#{data.size} bytes)")
      return
    end

    # Parse packet header
    packet_type = PacketType.new(data[0])
    stream_id = IO::ByteFormat::LittleEndian.decode(UInt32, data[1, 4])
    payload = data[5..-1]

    # Log packet information
    @logger.debug("Received packet: type=#{packet_type}, stream_id=#{stream_id}, payload_size=#{payload.size}")

    # Handle packet based on type
    case packet_type
    when PacketType::CONNECT
      handle_connect(ws, stream_id, payload)
    when PacketType::DATA
      handle_data(ws, stream_id, payload)
    when PacketType::CLOSE
      handle_close(ws, stream_id, payload)
    else
      @logger.warn("Received unknown packet type: #{packet_type}")
    end
  end

  # Handle CONNECT packet
  private def handle_connect(ws : HTTP::WebSocket, stream_id : UInt32, payload : Bytes)
    # Check if payload is too small
    if payload.size < 3
      @logger.warn("CONNECT payload too small")
      send_close(ws, stream_id, CloseReason::INVALID_INFO)
      return
    end

    # Parse connect payload
    stream_type = StreamType.new(payload[0])
    port = IO::ByteFormat::LittleEndian.decode(UInt16, payload[1, 2])
    hostname = String.new(payload[3..-1])

    @logger.info("New stream request: id=#{stream_id}, type=#{stream_type}, host=#{hostname}, port=#{port}")

    # Validate hostname and port
    if hostname.empty? || port <= 0
      @logger.warn("Invalid hostname or port")
      send_close(ws, stream_id, CloseReason::INVALID_INFO)
      return
    end

    # Check if stream ID already exists
    if @streams.has_key?(stream_id)
      @logger.warn("Stream ID #{stream_id} already exists")
      send_close(ws, stream_id, CloseReason::INVALID_INFO)
      return
    end

    # Create new stream
    stream = Stream.new(stream_id, hostname, port, stream_type)
    @streams[stream_id] = stream

    # Connect socket based on stream type
    case stream_type
    when StreamType::TCP
      handle_tcp_connect(ws, stream)
    when StreamType::UDP
      handle_udp_connect(ws, stream)
    end
  end

  # Handle TCP connection for a stream
  private def handle_tcp_connect(ws : HTTP::WebSocket, stream : Stream)
    # Initialize buffer for this stream
    stream.buffer_remaining = @max_buffer_size

    # Create a fiber to handle the connection
    spawn do
      begin
        # Try to establish TCP connection
        socket = TCPSocket.new(stream.host, stream.port, connect_timeout: @connect_timeout)

        # Store the socket in the stream
        stream.socket = socket

        # Send continue packet
        send_continue(ws, stream.stream_id, @max_buffer_size)

        # Create a fiber to handle incoming socket data
        spawn handle_tcp_incoming(ws, stream, socket)

        # Check if there are pending buffer items to send
        unless stream.buffer.empty?
          stream.buffer.each do |data|
            begin
              socket.write(data)
              socket.flush
            rescue ex
              @logger.error("Error writing to socket: #{ex.message}")
              send_close(ws, stream.stream_id, CloseReason::NETWORK_ERROR)
              stream.close_socket
              break
            end
          end
          stream.buffer.clear
        end

      rescue ex : Socket::ConnectError
        @logger.error("Connection refused: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::CONNECTION_REFUSED)
        @streams.delete(stream.stream_id)
      rescue ex : Socket::TimeoutError
        @logger.error("Connection timeout: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::CONNECTION_TIMEOUT)
        @streams.delete(stream.stream_id)
      rescue ex : Socket::Error
        @logger.error("Socket error: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::UNREACHABLE_HOST)
        @streams.delete(stream.stream_id)
      rescue ex
        @logger.error("Unexpected error: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::UNSPECIFIED)
        @streams.delete(stream.stream_id)
      end
    end
  end

  # Handle UDP connection for a stream
  private def handle_udp_connect(ws : HTTP::WebSocket, stream : Stream)
    begin
      # Create UDP socket
      socket = UDPSocket.new
      stream.socket = socket

      # For UDP, we don't need to send a CONTINUE packet as per the protocol

      # Create a fiber to handle incoming UDP data
      spawn handle_udp_incoming(ws, stream, socket)

      @logger.info("UDP socket created for stream #{stream.stream_id}")
    rescue ex
      @logger.error("Failed to create UDP socket: #{ex.message}")
      send_close(ws, stream.stream_id, CloseReason::UNSPECIFIED)
      @streams.delete(stream.stream_id)
    end
  end

  # Handle incoming data from TCP socket
  private def handle_tcp_incoming(ws : HTTP::WebSocket, stream : Stream, socket : TCPSocket)
    buffer = Bytes.new(16384) # 16KB buffer

    loop do
      begin
        bytes_read = socket.read(buffer)

        if bytes_read <= 0
          # Connection closed by the remote server
          @logger.info("Remote server closed connection for stream #{stream.stream_id}")
          send_close(ws, stream.stream_id, CloseReason::VOLUNTARY)
          stream.close_socket
          @streams.delete(stream.stream_id)
          break
        end

        # Send data to client
        data = buffer[0, bytes_read]
        send_data(ws, stream.stream_id, data)
      rescue ex : IO::TimeoutError
        @logger.error("TCP read timeout: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::TCP_TIMEOUT)
        stream.close_socket
        @streams.delete(stream.stream_id)
        break
      rescue ex : Socket::Error
        @logger.error("Socket error during read: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::NETWORK_ERROR)
        stream.close_socket
        @streams.delete(stream.stream_id)
        break
      rescue ex
        @logger.error("Unexpected error during read: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::UNSPECIFIED)
        stream.close_socket
        @streams.delete(stream.stream_id)
        break
      end
    end
  end

  # Handle incoming data from UDP socket
  private def handle_udp_incoming(ws : HTTP::WebSocket, stream : Stream, socket : UDPSocket)
    buffer = Bytes.new(16384) # 16KB buffer

    loop do
      begin
        bytes_read, client_addr = socket.receive(buffer)

        if bytes_read > 0
          # Send data to client
          data = buffer[0, bytes_read]
          send_data(ws, stream.stream_id, data)
        end
      rescue ex : Socket::Error
        @logger.error("Socket error during UDP receive: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::NETWORK_ERROR)
        stream.close_socket
        @streams.delete(stream.stream_id)
        break
      rescue ex
        @logger.error("Unexpected error during UDP receive: #{ex.message}")
        send_close(ws, stream.stream_id, CloseReason::UNSPECIFIED)
        stream.close_socket
        @streams.delete(stream.stream_id)
        break
      end
    end
  end

  # Handle DATA packet
  private def handle_data(ws : HTTP::WebSocket, stream_id : UInt32, payload : Bytes)
    stream = @streams[stream_id]?

    unless stream
      @logger.warn("Received DATA packet for non-existent stream #{stream_id}")
      send_close(ws, stream_id, CloseReason::UNSPECIFIED)
      return
    end

    unless stream.is_open
      @logger.warn("Received DATA packet for closed stream #{stream_id}")
      return
    end

    socket = stream.socket
    unless socket
      # Buffer the data until socket is connected
      stream.buffer << payload.dup
      return
    end

    begin
      case socket
      when TCPSocket
        # For TCP, send data directly to the socket
        socket.write(payload)
        socket.flush

        # Decrement buffer, send CONTINUE when needed
        if stream.buffer_remaining > 0
          stream.buffer_remaining -= 1

          # If buffer is empty, send a new CONTINUE packet
          if stream.buffer_remaining == 0
            send_continue(ws, stream_id, @max_buffer_size)
            stream.buffer_remaining = @max_buffer_size
          end
        end

      when UDPSocket
        # For UDP, send data to the specified host and port
        socket.send(payload, Socket::IPAddress.new(stream.host, stream.port))
      end
    rescue ex : Socket::Error
      @logger.error("Socket error during write: #{ex.message}")
      send_close(ws, stream_id, CloseReason::NETWORK_ERROR)
      stream.close_socket
      @streams.delete(stream_id)
    rescue ex
      @logger.error("Unexpected error during write: #{ex.message}")
      send_close(ws, stream_id, CloseReason::UNSPECIFIED)
      stream.close_socket
      @streams.delete(stream_id)
    end
  end

  # Handle CLOSE packet
  private def handle_close(ws : HTTP::WebSocket, stream_id : UInt32, payload : Bytes)
    if stream = @streams[stream_id]?
      reason = payload.size > 0 ? payload[0] : CloseReason::UNSPECIFIED.value
      @logger.info("Client requested close for stream #{stream_id} with reason #{reason}")

      # Close the socket
      stream.close_socket
      @streams.delete(stream_id)
    else
      @logger.warn("Received CLOSE packet for non-existent stream #{stream_id}")
    end
  end

  # Send CONTINUE packet
  private def send_continue(ws : HTTP::WebSocket, stream_id : UInt32, buffer_size : UInt32)
    packet = create_packet(PacketType::CONTINUE, stream_id, buffer_size)
    send_websocket_message(ws, packet)
  end

  # Send DATA packet
  private def send_data(ws : HTTP::WebSocket, stream_id : UInt32, data : Bytes)
    packet = create_packet(PacketType::DATA, stream_id, data)
    send_websocket_message(ws, packet)
  end

  # Send CLOSE packet
  private def send_close(ws : HTTP::WebSocket, stream_id : UInt32, reason : CloseReason)
    reason_byte = Bytes.new(1)
    reason_byte[0] = reason.value

    packet = create_packet(PacketType::CLOSE, stream_id, reason_byte)
    send_websocket_message(ws, packet)

    # Remove the stream from our active streams
    if stream = @streams[stream_id]?
      stream.close_socket
      @streams.delete(stream_id)
    end
  end

  # Create a packet according to the Wisp protocol
  private def create_packet(type : PacketType, stream_id : UInt32, payload : UInt32 | Bytes) : Bytes
    # Calculate the total packet size
    payload_size = payload.is_a?(UInt32) ? 4 : payload.size
    packet = Bytes.new(5 + payload_size)

    # Set packet type
    packet[0] = type.value

    # Set stream ID (little-endian)
    IO::ByteFormat::LittleEndian.encode(stream_id, packet[1, 4])

    # Set payload
    if payload.is_a?(UInt32)
      # For CONTINUE packets, payload is the buffer size
      IO::ByteFormat::LittleEndian.encode(payload, packet[5, 4])
    else
      # For other packets, copy the payload bytes
      payload.copy_to(packet + 5)
    end

    return packet
  end

  # Send a message over the WebSocket
  private def send_websocket_message(ws : HTTP::WebSocket, message : Bytes)
    begin
      ws.send(message)
    rescue ex
      @logger.error("Failed to send WebSocket message: #{ex.message}")
    end
  end
end

# Main entry point
host = ENV.fetch("WISP_HOST", "127.0.0.1")
port = ENV.fetch("WISP_PORT", "6001").to_i
path = ENV.fetch("WISP_PATH", "/")
buffer_size = ENV.fetch("WISP_BUFFER", "64").to_u32
timeout = ENV.fetch("WISP_TIMEOUT", "10.0").to_f

# Ensure path formatting
path = "/#{path.lstrip('/')}".chomp('/') + '/'

server = WispServer.new(
  host: host,
  port: port,
  path: path,
  max_buffer_size: buffer_size,
  connect_timeout: timeout
)

# Startup message
puts "Wisp Server v#{WispServer::VERSION}"
puts "Listening on ws://#{host}:#{port}#{path}"
puts "Buffer size: #{buffer_size} packets"
puts "Connection timeout: #{timeout} seconds"

server.start

