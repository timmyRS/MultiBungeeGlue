package de.timmyrs;

import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.ServerPing;
import net.md_5.bungee.api.chat.ComponentBuilder;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.ProxyPingEvent;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;
import net.md_5.bungee.event.EventHandler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.regex.Pattern;

public class MultiBungeeGlue extends Plugin implements Listener
{
	static MultiBungeeGlue instance;
	static Configuration config;
	static final ArrayList<Connection> connections = new ArrayList<>();
	static final ArrayList<GluedPlayer> players = new ArrayList<>();
	static final BroadcastConnection broadcaster = new BroadcastConnection();
	private File configFile;
	private ConnectionListener connectionListener;
	private ConnectionMaintainer connectionMaintainer;
	private static ConfigurationProvider configProvider;
	final static HashMap<String, String> bannedPlayers = new HashMap<>();

	@Override
	public void onEnable()
	{
		try
		{
			final File dataFolder = getDataFolder();
			if(!dataFolder.exists() && !dataFolder.mkdir())
			{
				throw new IOException("Failed to create " + dataFolder.getPath());
			}
			configFile = new File(dataFolder, "config.yml");
			if(!configFile.exists() && !configFile.createNewFile())
			{
				throw new IOException("Failed to create " + configFile.getPath());
			}
			configProvider = ConfigurationProvider.getProvider(YamlConfiguration.class);
			config = configProvider.load(configFile);
			final boolean configured;
			if(config.contains("otherBungees"))
			{
				configured = true;
			}
			else
			{
				final ArrayList<String> otherBungees = new ArrayList<>();
				otherBungees.add("1.2.3.4");
				otherBungees.add("1:2:3::4");
				config.set("otherBungees", otherBungees);
				configured = false;
			}
			if(!config.contains("commands.lobbyServer"))
			{
				config.set("commands.lobbyServer", "lobby");
			}
			if(!config.contains("commands.aliasBan"))
			{
				config.set("commands.aliasBan", false);
			}
			if(!config.contains("communication.port"))
			{
				config.set("communication.port", (short) 25389);
			}
			if(!config.contains("communication.sharedSecret"))
			{
				config.set("communication.sharedSecret", "");
			}
			if(!config.contains("motd.overwriteOnlinePlayers"))
			{
				config.set("motd.overwriteOnlinePlayers", true);
			}
			if(config.contains("bannedPlayers"))
			{
				for(String uuid : config.getSection("bannedPlayers").getKeys())
				{
					bannedPlayers.put(uuid, config.getString("bannedPlayers." + uuid));
				}
			}
			else
			{
				config.set("bannedPlayers", new HashMap<String, String>());
			}
			configProvider.save(config, configFile);
			if(configured)
			{
				instance = this;
				connectionListener = new ConnectionListener();
				connectionMaintainer = new ConnectionMaintainer();
				getProxy().getPluginManager().registerListener(this, this);
				getProxy().getPluginManager().registerCommand(this, new LobbyCommand());
				getProxy().getPluginManager().registerCommand(this, new AlertCommand());
				getProxy().getPluginManager().registerCommand(this, new SendCommand());
				getProxy().getPluginManager().registerCommand(this, new BanCommand(config.getBoolean("commands.aliasBan")));
				getProxy().getPluginManager().registerCommand(this, new UnbanCommand(config.getBoolean("commands.aliasBan")));
				getProxy().getPluginManager().registerCommand(this, new EndCommand());
			}
			else
			{
				getLogger().log(Level.WARNING, "Please configure MultiBungeeGlue and then restart.");
			}
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
	}

	void saveConfig() throws IOException
	{
		configProvider.save(config, configFile);
	}

	@Override
	public void onDisable()
	{
		if(connectionListener != null && connectionListener.isAlive())
		{
			connectionListener.interrupt();
		}
		if(connectionMaintainer != null && connectionMaintainer.isAlive())
		{
			connectionMaintainer.interrupt();
		}
		final ArrayList<Connection> _connections;
		synchronized(connections)
		{
			_connections = new ArrayList<>(connections);
		}
		for(Connection c : _connections)
		{
			c.close(false);
		}
	}

	@EventHandler
	public void onProxyPing(ProxyPingEvent e)
	{
		if(config.getBoolean("motd.overwriteOnlinePlayers"))
		{
			final ServerPing.Players responsePlayers = e.getResponse().getPlayers();
			responsePlayers.setSample(new ServerPing.PlayerInfo[]{});
			synchronized(players)
			{
				responsePlayers.setOnline(players.size());
			}
		}
	}

	@EventHandler
	public void onLogin(LoginEvent e)
	{
		synchronized(MultiBungeeGlue.bannedPlayers)
		{
			final String banReason = MultiBungeeGlue.bannedPlayers.get(Pattern.compile("^([A-Fa-f0-9]{8})([A-Fa-f0-9]{4})([A-Fa-f0-9]{4})([A-Fa-f0-9]{4})([A-Fa-f0-9]{12})$").matcher(e.getLoginResult().getId()).replaceAll("$1-$2-$3-$4-$5"));
			if(banReason != null)
			{
				e.setCancelled(true);
				e.setCancelReason(TextComponent.fromLegacyText("§4You are banned from this server: " + banReason));
			}
		}
	}

	@EventHandler
	public void onPostLogin(PostLoginEvent e)
	{
		synchronized(MultiBungeeGlue.players)
		{
			new GluedPlayer(e.getPlayer());
		}
	}

	@EventHandler
	public void onDisconnect(PlayerDisconnectEvent e)
	{
		synchronized(MultiBungeeGlue.players)
		{
			final GluedPlayer p = GluedPlayer.get(e.getPlayer().getUniqueId());
			if(p != null)
			{
				p.unglue();
			}
		}
	}
}

class Connection extends Thread
{
	final String ip;
	private final Socket socket;
	final OutputStream os;
	boolean authorized = false;

	Connection()
	{
		this.ip = "";
		this.socket = null;
		this.os = new ByteArrayOutputStream();
	}

	Connection(Socket socket) throws IOException
	{
		this(socket.getRemoteSocketAddress().toString().substring(1).split(":")[0], socket, false);
	}

	Connection(String ip, Socket socket) throws IOException
	{
		this(ip, socket, true);
	}

	private Connection(String ip, Socket socket, boolean authorize) throws IOException
	{
		this.ip = ip;
		this.socket = socket;
		this.os = socket.getOutputStream();
		this.start();
		if(authorize)
		{
			this.writeInt(Packet.values().length);
			this.writeString(MultiBungeeGlue.config.getString("communication.sharedSecret"));
			this.flush();
			this.authorized = true;
		}
		synchronized(MultiBungeeGlue.players)
		{
			for(GluedPlayer p : MultiBungeeGlue.players)
			{
				p.sendGlue(this);
			}
		}
		synchronized(MultiBungeeGlue.bannedPlayers)
		{
			this.writeByte((byte) Packet.SYNC_BANNED_PLAYERS.ordinal());
			this.writeInt(MultiBungeeGlue.bannedPlayers.size());
			for(String uuid : MultiBungeeGlue.bannedPlayers.keySet())
			{
				this.writeUUID(UUID.fromString(uuid));
			}
			this.flush();
		}
	}

	void close(boolean forgetPlayers)
	{
		synchronized(MultiBungeeGlue.connections)
		{
			if(!this.isInterrupted())
			{
				this.interrupt();
			}
			if(!this.socket.isClosed())
			{
				try
				{
					this.socket.close();
				}
				catch(IOException ignored)
				{
				}
			}
			MultiBungeeGlue.connections.remove(this);
			if(forgetPlayers)
			{
				synchronized(MultiBungeeGlue.players)
				{
					final ArrayList<GluedPlayer> _players = new ArrayList<>(MultiBungeeGlue.players);
					for(GluedPlayer p : _players)
					{
						if(p.proxy.equals(this.ip))
						{
							MultiBungeeGlue.players.remove(p);
						}
					}
				}
			}
		}
	}

	void writeByte(byte value) throws IOException
	{
		this.os.write(value);
	}

	private void writeInt(int value) throws IOException
	{
		byte[] result = new byte[4];
		for(int i = 3; i >= 0; i--)
		{
			result[i] = (byte) (value & 0xFF);
			value >>= 8;
		}
		for(byte b : result)
		{
			this.writeByte(b);
		}
	}

	void writeString(String value) throws IOException
	{
		this.writeInt(value.length());
		for(byte b : value.getBytes(StandardCharsets.UTF_8))
		{
			this.writeByte(b);
		}
	}

	private void writeLong(long value) throws IOException
	{
		byte[] result = new byte[8];
		for(int i = 7; i >= 0; i--)
		{
			result[i] = (byte) (value & 0xFF);
			value >>= 8;
		}
		for(byte b : result)
		{
			this.writeByte(b);
		}
	}

	void writeUUID(UUID uuid) throws IOException
	{
		this.writeLong(uuid.getMostSignificantBits());
		this.writeLong(uuid.getLeastSignificantBits());
	}

	void flush() throws IOException
	{
		this.os.flush();
	}

	private static int readInt(InputStream is) throws IOException
	{
		int result = 0;
		for(int i = 0; i < 4; i++)
		{
			result <<= 8;
			result |= (is.read() & 0xFF);
		}
		return result;
	}

	private static long readLong(InputStream is) throws IOException
	{
		long result = 0;
		for(int i = 0; i < 8; i++)
		{
			result <<= 8;
			result |= (is.read() & 0xFF);
		}
		return result;
	}

	private static String readString(InputStream is) throws IOException
	{
		final int strlength = readInt(is);
		final byte[] bytes = new byte[strlength];
		int i = 0;
		while(i < strlength)
		{
			bytes[i++] = (byte) is.read();
		}
		return new String(bytes, StandardCharsets.UTF_8);
	}

	private static UUID readUUID(InputStream is) throws IOException
	{
		return new UUID(readLong(is), readLong(is));
	}

	@Override
	public void run()
	{
		try
		{
			final InputStream is = this.socket.getInputStream();
			do
			{
				if(authorized)
				{
					if(!handlePacket(is))
					{
						break;
					}
				}
				else if(readInt(is) == Packet.values().length && readString(is).equals(MultiBungeeGlue.config.getString("communication.sharedSecret")))
				{
					authorized = true;
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, ip + " successfully authorized.");
				}
				else
				{
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, ip + " failed to authorize — closed connection.");
					break;
				}
			}
			while(!this.isInterrupted());
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
		finally
		{
			this.close(true);
		}
	}

	boolean handlePacket(final InputStream is) throws IOException
	{
		final int packetId = is.read();
		if(packetId == -1)
		{
			return false;
		}
		final Packet packet = Packet.fromOrdinal(packetId);
		if(packet == Packet.UNKNOWN)
		{
			MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Received unknown packet ID: " + packetId);
		}
		else
		{
			MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Received " + packet + " packet.");
			if(packet == Packet.END)
			{
				ProxyServer.getInstance().stop();
			}
			else if(packet == Packet.ALERT)
			{
				ProxyServer.getInstance().broadcast(TextComponent.fromLegacyText("§8[§4Alert§8]§r " + readString(is)));
			}
			else if(packet == Packet.GLUE_PLAYER)
			{
				final UUID uuid = readUUID(is);
				final String name = readString(is);
				final boolean unbannable = is.read() == 1;
				synchronized(MultiBungeeGlue.players)
				{
					new GluedPlayer(this.ip, uuid, name, unbannable);
				}
			}
			else if(packet == Packet.UNGLUE_PLAYER)
			{
				synchronized(MultiBungeeGlue.players)
				{
					MultiBungeeGlue.players.remove(GluedPlayer.get(readUUID(is)));
				}
			}
			else if(packet == Packet.SEND_ALL)
			{
				final ServerInfo serverInfo = ProxyServer.getInstance().getServerInfo(readString(is));
				if(serverInfo != null)
				{
					for(ProxiedPlayer p : ProxyServer.getInstance().getPlayers())
					{
						if(!p.getServer().getInfo().equals(serverInfo))
						{
							p.connect(serverInfo);
						}
					}
				}
			}
			else if(packet == Packet.SEND_SERVER)
			{
				final String fromServer = readString(is);
				final ServerInfo serverInfo = ProxyServer.getInstance().getServerInfo(readString(is));
				if(serverInfo != null)
				{
					for(ProxiedPlayer p : ProxyServer.getInstance().getPlayers())
					{
						if(p.getServer().getInfo().getName().equals(fromServer) && !p.getServer().getInfo().equals(serverInfo))
						{
							p.connect(serverInfo);
						}
					}
				}
			}
			else if(packet == Packet.SEND_PLAYER)
			{
				final ProxiedPlayer p = ProxyServer.getInstance().getPlayer(readString(is));
				final ServerInfo serverInfo = ProxyServer.getInstance().getServerInfo(readString(is));
				if(p != null && serverInfo != null && !p.getServer().getInfo().equals(serverInfo))
				{
					p.connect(serverInfo);
				}
			}
			else if(packet == Packet.SYNC_BANNED_PLAYERS)
			{
				final ArrayList<String> remoteBannedPlayers = new ArrayList<>();
				for(int i = readInt(is); i > 0; i--)
				{
					remoteBannedPlayers.add(readUUID(is).toString());
				}
				synchronized(MultiBungeeGlue.bannedPlayers)
				{
					for(Map.Entry<String, String> ban : MultiBungeeGlue.bannedPlayers.entrySet())
					{
						if(!remoteBannedPlayers.contains(ban.getKey()))
						{
							writeByte((byte) Packet.BAN_PLAYER.ordinal());
							writeUUID(UUID.fromString(ban.getKey()));
							writeString(ban.getValue());
							flush();
						}
					}
				}
			}
			else if(packet == Packet.BAN_PLAYER)
			{
				final UUID u = readUUID(is);
				final GluedPlayer p = GluedPlayer.get(u);
				final String reason = readString(is);
				if(p != null && p.isLocal())
				{
					p.getProxied().disconnect(TextComponent.fromLegacyText("§4You have been banned from this server: " + reason));
				}
				synchronized(MultiBungeeGlue.bannedPlayers)
				{
					MultiBungeeGlue.bannedPlayers.put(u.toString(), reason);
					MultiBungeeGlue.config.set("bannedPlayers", MultiBungeeGlue.bannedPlayers);
				}
				MultiBungeeGlue.instance.saveConfig();
			}
			else if(packet == Packet.UNBAN_PLAYER)
			{
				synchronized(MultiBungeeGlue.bannedPlayers)
				{
					MultiBungeeGlue.bannedPlayers.remove(readString(is));
					MultiBungeeGlue.config.set("bannedPlayers", MultiBungeeGlue.bannedPlayers);
				}
				MultiBungeeGlue.instance.saveConfig();
			}
		}
		return true;
	}
}

class BroadcastConnection extends Connection
{
	BroadcastConnection()
	{
		super();
	}

	@Override
	void flush()
	{
		final byte[] bytes = ((ByteArrayOutputStream) os).toByteArray();
		((ByteArrayOutputStream) os).reset();
		try
		{
			handlePacket(new ByteArrayInputStream(bytes));
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
		synchronized(MultiBungeeGlue.connections)
		{
			for(Connection c : MultiBungeeGlue.connections)
			{
				if(c.authorized)
				{
					try
					{
						c.os.write(bytes);
						c.flush();
					}
					catch(IOException e)
					{
						e.printStackTrace();
					}
				}
			}
		}
	}
}

class ConnectionListener extends Thread
{
	private final ServerSocket serverSocket;

	ConnectionListener() throws IOException
	{
		super("ConnectionListener");
		this.serverSocket = new ServerSocket(MultiBungeeGlue.config.getShort("communication.port"));
		this.start();
	}

	@Override
	public void run()
	{
		//noinspection InfiniteLoopStatement
		do
		{
			try
			{
				Connection connection = new Connection(serverSocket.accept());
				if(MultiBungeeGlue.config.getStringList("otherBungees").contains(connection.ip))
				{
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Accepted connection from " + connection.ip);
					synchronized(MultiBungeeGlue.connections)
					{
						for(Connection c : MultiBungeeGlue.connections)
						{
							if(c.ip.equals(connection.ip))
							{
								c.close(false);
								break;
							}
						}
					}
					MultiBungeeGlue.connections.add(connection);
				}
				else
				{
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Denied connection from " + connection.ip);
					connection.close(false);
				}
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}

		}
		while(!this.isInterrupted());
	}
}

class ConnectionMaintainer extends Thread
{
	ConnectionMaintainer()
	{
		super("ConnectionMaintainer");
		this.start();
	}

	@Override
	public void run()
	{
		try
		{
			//noinspection InfiniteLoopStatement
			do
			{

				final ArrayList<String> missingPeers = new ArrayList<>(MultiBungeeGlue.config.getStringList("otherBungees"));
				synchronized(MultiBungeeGlue.connections)
				{
					for(Connection c : MultiBungeeGlue.connections)
					{
						missingPeers.remove(c.ip);
					}
				}
				for(String ip : missingPeers)
				{
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Connecting to missing peer at " + ip);
					try
					{
						synchronized(MultiBungeeGlue.connections)
						{
							MultiBungeeGlue.connections.add(new Connection(ip, new Socket(ip, MultiBungeeGlue.config.getShort("communication.port"))));
						}
					}
					catch(IOException e)
					{
						e.printStackTrace();
					}
				}
				final ArrayList<Connection> connections;
				synchronized(MultiBungeeGlue.connections)
				{
					connections = new ArrayList<>(MultiBungeeGlue.connections);
				}
				final ArrayList<GluedPlayer> _players;
				synchronized(MultiBungeeGlue.players)
				{
					_players = new ArrayList<>(MultiBungeeGlue.players);
				}
				for(GluedPlayer p : _players)
				{
					if(p.isLocal())
					{
						continue;
					}
					boolean found = false;
					for(Connection c : connections)
					{
						if(c.ip.equals(p.proxy))
						{
							found = true;
							break;
						}
					}
					if(!found)
					{
						synchronized(MultiBungeeGlue.players)
						{
							MultiBungeeGlue.players.remove(p);
						}
					}
				}
				Thread.sleep(10000);
			}
			while(!this.isInterrupted());
		}
		catch(InterruptedException ignored)
		{
		}
	}
}

enum Packet
{
	END,
	ALERT,
	GLUE_PLAYER,
	UNGLUE_PLAYER,
	SEND_ALL,
	SEND_SERVER,
	SEND_PLAYER,
	SYNC_BANNED_PLAYERS,
	BAN_PLAYER,
	UNBAN_PLAYER,
	UNKNOWN;

	public static Packet fromOrdinal(int o)
	{
		for(Packet p : Packet.values())
		{
			if(p.ordinal() == o)
			{
				return p;
			}
		}
		return UNKNOWN;
	}
}

class GluedPlayer
{
	final String proxy;
	final UUID uuid;
	final String name;
	final boolean unbannable;

	GluedPlayer(ProxiedPlayer player)
	{
		this("", player.getUniqueId(), player.getName(), player.hasPermission("multibungeeglue.unbannable"));
		synchronized(MultiBungeeGlue.connections)
		{
			for(Connection c : MultiBungeeGlue.connections)
			{
				try
				{
					this.sendGlue(c);
				}
				catch(IOException e)
				{
					e.printStackTrace();
				}
			}
		}
	}

	GluedPlayer(String proxy, UUID uuid, String name, boolean unbannable)
	{
		this.proxy = proxy;
		this.uuid = uuid;
		this.name = name;
		this.unbannable = unbannable;
		synchronized(MultiBungeeGlue.players)
		{
			final GluedPlayer p = GluedPlayer.get(name);
			if(p != null)
			{
				if(p.isLocal())
				{
					p.getProxied().disconnect(TextComponent.fromLegacyText("You connected from a different location."));
				}
				MultiBungeeGlue.players.remove(p);
			}
			MultiBungeeGlue.players.add(this);
		}
	}

	void sendGlue(Connection c) throws IOException
	{
		c.writeByte((byte) Packet.GLUE_PLAYER.ordinal());
		c.writeUUID(uuid);
		c.writeString(name);
		c.writeByte((byte) (unbannable ? 1 : 0));
		c.flush();
	}

	void unglue()
	{
		synchronized(MultiBungeeGlue.connections)
		{
			for(Connection c : MultiBungeeGlue.connections)
			{
				try
				{
					c.writeByte((byte) Packet.UNGLUE_PLAYER.ordinal());
					c.writeUUID(uuid);
					c.flush();
				}
				catch(IOException e)
				{
					e.printStackTrace();
				}
			}
		}
		synchronized(MultiBungeeGlue.players)
		{
			MultiBungeeGlue.players.remove(this);
		}
	}

	boolean isLocal()
	{
		return this.proxy.equals("");
	}

	ProxiedPlayer getProxied()
	{
		return ProxyServer.getInstance().getPlayer(uuid);
	}

	static GluedPlayer get(String name)
	{
		synchronized(MultiBungeeGlue.players)
		{
			for(GluedPlayer p : MultiBungeeGlue.players)
			{
				if(p.name.equalsIgnoreCase(name))
				{
					return p;
				}
			}
		}
		return null;
	}

	static GluedPlayer get(UUID uuid)
	{
		synchronized(MultiBungeeGlue.players)
		{
			for(GluedPlayer p : MultiBungeeGlue.players)
			{
				if(p.uuid.equals(uuid))
				{
					return p;
				}
			}
		}
		return null;
	}
}

// Commands

class LobbyCommand extends Command
{
	LobbyCommand()
	{
		super("lobby", "multibungeeglue.command.lobby", "hub");
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		if(s instanceof ProxiedPlayer)
		{
			final ProxiedPlayer p = (ProxiedPlayer) s;
			if(p.getServer().getInfo().getName().equals(MultiBungeeGlue.config.getString("commands.lobbyServer")))
			{
				p.sendMessage(new ComponentBuilder("You're already in the lobby.").color(ChatColor.RED).create());
			}
			else
			{
				final ServerInfo serverInfo = ProxyServer.getInstance().getServerInfo(MultiBungeeGlue.config.getString("commands.lobbyServer"));
				if(serverInfo == null)
				{
					s.sendMessage(new ComponentBuilder("MultiBungeeGlue is misconfigured — " + MultiBungeeGlue.config.getString("commands.lobbyServer") + " does not exist.").color(ChatColor.RED).create());
				}
				else
				{
					p.connect(serverInfo);
				}
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("This command is only for players.").color(ChatColor.RED).create());
		}
	}
}

class AlertCommand extends Command
{
	AlertCommand()
	{
		super("malert", "multibungeeglue.command.alert", "alert");
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		if(args.length > 0)
		{
			final StringBuilder builder = new StringBuilder(args[0]);
			if(args.length > 1)
			{
				for(int i = 1; i < args.length; i++)
				{
					builder.append(" ").append(args[i]);
				}
			}
			final String message = builder.toString();
			try
			{
				MultiBungeeGlue.broadcaster.writeByte((byte) Packet.ALERT.ordinal());
				MultiBungeeGlue.broadcaster.writeString(message);
				MultiBungeeGlue.broadcaster.flush();
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /malert <message>").color(ChatColor.RED).create());
		}
	}
}

class SendCommand extends Command
{
	SendCommand()
	{
		super("msend", "multibungeeglue.command.send", "send");
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		if(args.length == 2)
		{
			final ServerInfo targetServerInfo = ProxyServer.getInstance().getServerInfo(args[1]);
			if(targetServerInfo == null)
			{
				s.sendMessage(new ComponentBuilder("Unknown server: " + args[1]).color(ChatColor.RED).create());
			}
			else if(args[0].equalsIgnoreCase("all"))
			{
				try
				{
					MultiBungeeGlue.broadcaster.writeByte((byte) Packet.SEND_ALL.ordinal());
					MultiBungeeGlue.broadcaster.writeString(args[1]);
					MultiBungeeGlue.broadcaster.flush();
				}
				catch(IOException e)
				{
					e.printStackTrace();
				}
			}
			else
			{
				final ServerInfo serverInfo = ProxyServer.getInstance().getServerInfo(args[0]);
				if(serverInfo != null)
				{
					try
					{
						MultiBungeeGlue.broadcaster.writeByte((byte) Packet.SEND_SERVER.ordinal());
						MultiBungeeGlue.broadcaster.writeString(args[0]);
						MultiBungeeGlue.broadcaster.writeString(args[1]);
						MultiBungeeGlue.broadcaster.flush();
					}
					catch(IOException e)
					{
						e.printStackTrace();
					}
				}
				else
				{
					final GluedPlayer p = GluedPlayer.get(args[0]);
					if(p != null)
					{
						if(p.isLocal())
						{
							p.getProxied().connect(targetServerInfo);
						}
						else
						{
							for(Connection c : MultiBungeeGlue.connections)
							{
								if(c.ip.equals(p.proxy))
								{
									try
									{
										c.writeByte((byte) Packet.SEND_PLAYER.ordinal());
										c.writeString(args[0]);
										c.writeString(args[1]);
										c.flush();
									}
									catch(IOException e)
									{
										e.printStackTrace();
									}
								}
							}
						}
					}
					else
					{
						s.sendMessage(new ComponentBuilder(args[0] + " is not a known server or player.").color(ChatColor.RED).create());
					}
				}
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /msend <all|server|player> <target server>").color(ChatColor.RED).create());
		}
	}
}

class BanCommand extends Command
{
	BanCommand(boolean aliasBan)
	{
		super("mban", "multibungeeglue.command.ban", aliasBan ? new String[]{"ban"} : new String[0]);
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		if(args.length > 0)
		{
			final GluedPlayer p = GluedPlayer.get(args[0]);
			if(p == null)
			{
				s.sendMessage(new ComponentBuilder("Couldn't find " + args[0]).color(ChatColor.RED).create());
			}
			else if(p.unbannable)
			{
				s.sendMessage(new ComponentBuilder(p.name + " is unbannable.").color(ChatColor.RED).create());
			}
			else
			{
				final String reason;
				if(args.length > 1)
				{
					final StringBuilder builder = new StringBuilder(args[1]);
					if(args.length > 2)
					{
						for(int i = 2; i < args.length; i++)
						{
							builder.append(" ").append(args[i]);
						}
					}
					reason = builder.toString();
				}
				else
				{
					reason = "Banned by an operator.";
				}
				try
				{
					MultiBungeeGlue.broadcaster.writeByte((byte) Packet.BAN_PLAYER.ordinal());
					MultiBungeeGlue.broadcaster.writeUUID(p.uuid);
					MultiBungeeGlue.broadcaster.writeString(reason);
					MultiBungeeGlue.broadcaster.flush();
				}
				catch(IOException e)
				{
					e.printStackTrace();
				}
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /mban <player> [reason]").color(ChatColor.RED).create());
		}
	}
}

class UnbanCommand extends Command
{
	UnbanCommand(boolean aliasBan)
	{
		super("munban", "multibungeeglue.command.unban", aliasBan ? new String[]{"mpardon", "pardon", "unban"} : new String[]{"mpardon"});
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		if(args.length > 0)
		{
			try
			{
				MultiBungeeGlue.broadcaster.writeByte((byte) Packet.UNBAN_PLAYER.ordinal());
				MultiBungeeGlue.broadcaster.writeString(args[0]);
				MultiBungeeGlue.broadcaster.flush();
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /munban <uuid>").color(ChatColor.RED).create());
		}
	}
}

class EndCommand extends Command
{
	EndCommand()
	{
		super("mend", "multibungeeglue.command.end");
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		synchronized(MultiBungeeGlue.connections)
		{
			for(Connection c : MultiBungeeGlue.connections)
			{
				try
				{
					c.writeByte((byte) Packet.END.ordinal());
					c.flush();
				}
				catch(IOException e)
				{
					e.printStackTrace();
				}
			}
		}
		ProxyServer.getInstance().stop();
	}
}
