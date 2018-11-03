package de.timmyrs;

import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.ServerPing;
import net.md_5.bungee.api.chat.ComponentBuilder;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.ProxiedPlayer;
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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;
import java.util.logging.Level;

public class MultiBungeeGlue extends Plugin implements Listener
{
	static MultiBungeeGlue instance;
	static Configuration config;
	static final ArrayList<Connection> connections = new ArrayList<>();
	static final ArrayList<GluedPlayer> players = new ArrayList<>();
	private ConnectionListener connectionListener;
	private ConnectionMaintainer connectionMaintainer;

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
			final File configFile = new File(dataFolder, "config.yml");
			if(!configFile.exists() && !configFile.createNewFile())
			{
				throw new IOException("Failed to create " + configFile.getPath());
			}
			final ConfigurationProvider configProvider = ConfigurationProvider.getProvider(YamlConfiguration.class);
			config = configProvider.load(configFile);
			if(!config.contains("lobbyServer"))
			{
				config.set("lobbyServer", "lobby");
			}
			if(!config.contains("overwriteOnlinePlayers"))
			{
				config.set("overwriteOnlinePlayers", true);
			}
			if(!config.contains("communicationPort"))
			{
				config.set("communicationPort", (short) 25389);
			}
			if(config.contains("otherBungees"))
			{
				configProvider.save(config, configFile);
				instance = this;
				connectionListener = new ConnectionListener();
				connectionMaintainer = new ConnectionMaintainer();
				getProxy().getPluginManager().registerListener(this, this);
				getProxy().getPluginManager().registerCommand(this, new AlertCommand());
				getProxy().getPluginManager().registerCommand(this, new EndCommand());
				getProxy().getPluginManager().registerCommand(this, new LobbyCommand());
				getProxy().getPluginManager().registerCommand(this, new SendCommand());
			}
			else
			{
				final ArrayList<String> otherBungees = new ArrayList<>();
				otherBungees.add("1.2.3.4");
				otherBungees.add("1:2:3::4");
				config.set("otherBungees", otherBungees);
				configProvider.save(config, configFile);
				getLogger().log(Level.WARNING, "Please configure MultiBungeeGlue and then restart.");
			}
		}
		catch(IOException e)
		{
			e.printStackTrace();
		}
	}

	@Override
	public void onDisable()
	{
		connectionListener.interrupt();
		connectionMaintainer.interrupt();
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
		if(config.getBoolean("overwriteOnlinePlayers"))
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
	private final OutputStream os;

	Connection(Socket socket) throws IOException
	{
		this(socket.getRemoteSocketAddress().toString().substring(1).split(":")[0], socket);
	}

	Connection(String ip, Socket socket) throws IOException
	{
		this.ip = ip;
		this.socket = socket;
		this.os = socket.getOutputStream();
		this.start();
		synchronized(MultiBungeeGlue.players)
		{
			for(GluedPlayer p : MultiBungeeGlue.players)
			{
				p.sendGlue(this);
			}
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
				final int packetId = is.read();
				if(packetId == -1)
				{
					break;
				}
				final Packet packet = Packet.fromOrdinal(packetId);
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
					UUID uuid = readUUID(is);
					String name = readString(is);
					synchronized(MultiBungeeGlue.players)
					{
						new GluedPlayer(this.ip, uuid, name);
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
				else
				{
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Received unknown packet: " + packetId);
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
}

class ConnectionListener extends Thread
{
	private final ServerSocket serverSocket;

	ConnectionListener() throws IOException
	{
		super("ConnectionListener");
		this.serverSocket = new ServerSocket(MultiBungeeGlue.config.getShort("communicationPort"));
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
				if(MultiBungeeGlue.config.getList("otherBungees").contains(connection.ip))
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

				//noinspection unchecked
				final ArrayList<String> missingPeers = new ArrayList<>((Collection<? extends String>) MultiBungeeGlue.config.getList("otherBungees"));
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
							MultiBungeeGlue.connections.add(new Connection(ip, new Socket(ip, MultiBungeeGlue.config.getShort("communicationPort"))));
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
	UNKNOWN,
	END,
	ALERT,
	GLUE_PLAYER,
	UNGLUE_PLAYER,
	SEND_ALL,
	SEND_SERVER,
	SEND_PLAYER;

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
	private final UUID uuid;
	private final String name;

	GluedPlayer(ProxiedPlayer player)
	{
		this("", player.getUniqueId(), player.getName());
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

	GluedPlayer(String proxy, UUID uuid, String name)
	{
		this.proxy = proxy;
		this.uuid = uuid;
		this.name = name;
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
				if(p.name.equals(name))
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
			ProxyServer.getInstance().broadcast(TextComponent.fromLegacyText("§8[§4Alert§8]§r " + message));
			synchronized(MultiBungeeGlue.connections)
			{
				for(Connection c : MultiBungeeGlue.connections)
				{
					try
					{
						c.writeByte((byte) Packet.ALERT.ordinal());
						c.writeString(message);
						c.flush();
					}
					catch(IOException e)
					{
						e.printStackTrace();
					}
				}
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /alert <message>").color(ChatColor.RED).create());
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
			if(p.getServer().getInfo().getName().equals(MultiBungeeGlue.config.getString("lobbyServer")))
			{
				p.sendMessage(new ComponentBuilder("You're already in the lobby.").color(ChatColor.RED).create());
			}
			else
			{
				final ServerInfo serverInfo = ProxyServer.getInstance().getServerInfo(MultiBungeeGlue.config.getString("lobbyServer"));
				if(serverInfo == null)
				{
					s.sendMessage(new ComponentBuilder("MultiBungeeGlue is misconfigured — " + MultiBungeeGlue.config.getString("lobbyServer") + " does not exist.").color(ChatColor.RED).create());
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
				for(Connection c : MultiBungeeGlue.connections)
				{
					try
					{
						c.writeByte((byte) Packet.SEND_ALL.ordinal());
						c.writeString(args[1]);
						c.flush();
					}
					catch(IOException e)
					{
						e.printStackTrace();
					}
				}
				for(ProxiedPlayer p : ProxyServer.getInstance().getPlayers())
				{
					p.connect(targetServerInfo);
				}
			}
			else
			{
				final ServerInfo serverInfo = ProxyServer.getInstance().getServerInfo(args[0]);
				if(serverInfo != null)
				{
					for(Connection c : MultiBungeeGlue.connections)
					{
						try
						{
							c.writeByte((byte) Packet.SEND_SERVER.ordinal());
							c.writeString(args[0]);
							c.writeString(args[1]);
							c.flush();
						}
						catch(IOException e)
						{
							e.printStackTrace();
						}
					}
					for(ProxiedPlayer p : ProxyServer.getInstance().getPlayers())
					{
						if(p.getServer().getInfo().equals(serverInfo))
						{
							p.connect(targetServerInfo);
						}
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
					else
					{
						s.sendMessage(new ComponentBuilder(args[0] + " is not a known server or player.").color(ChatColor.RED).create());
					}
				}
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /send <all|server|player> <target server>").color(ChatColor.RED).create());
		}
	}
}
