package de.timmyrs;

import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.ChatMessageType;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.ServerPing;
import net.md_5.bungee.api.chat.BaseComponent;
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

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.logging.Level;
import java.util.regex.Pattern;

public class MultiBungeeGlue extends Plugin implements Listener
{
	private final Pattern hypenlessUUIDPattern = Pattern.compile("^([A-Fa-f0-9]{8})([A-Fa-f0-9]{4})([A-Fa-f0-9]{4})([A-Fa-f0-9]{4})([A-Fa-f0-9]{12})$");
	static final Pattern socketAddressPattern = Pattern.compile("^/([0-9.:\\[\\]]+):[0-9]{4,5}$");
	static MultiBungeeGlue instance;
	static Configuration config;
	static final ArrayList<Connection> connections = new ArrayList<>();
	static final ArrayList<GluedPlayer> players = new ArrayList<>();
	static final ArrayList<String> otherBungees = new ArrayList<>();
	static final BroadcastConnection broadcaster = new BroadcastConnection();
	static final LoopbackConnection loopback = new LoopbackConnection();
	private File configFile;
	private boolean configured = false;
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
			if(config.contains("bungees"))
			{
				final List<String> bungees = config.getStringList("bungees");
				if(bungees.size() != 2 || !bungees.get(0).equals("1.2.3.4") || !bungees.get(1).equals("1:2:3::4"))
				{
					otherBungees.addAll(bungees);
					configured = true;
				}
			}
			else
			{
				final ArrayList<String> bungees = new ArrayList<>();
				bungees.add("1.2.3.4");
				bungees.add("1:2:3::4");
				config.set("bungees", bungees);
			}
			if(!config.contains("commands.lobbyServer"))
			{
				config.set("commands.lobbyServer", "lobby");
			}
			if(!config.contains("commands.aliasTell"))
			{
				config.set("commands.aliasTell", true);
			}
			if(!config.contains("commands.tellSent"))
			{
				config.set("commands.tellSent", "§7You whisper to %recipient%: %message%");
			}
			if(!config.contains("commands.tellReceived"))
			{
				config.set("commands.tellReceived", "§7%sender% whispers to you: %message%");
			}
			if(!config.contains("commands.aliasList"))
			{
				config.set("commands.aliasList", false);
			}
			if(!config.contains("commands.aliasBan"))
			{
				config.set("commands.aliasBan", true);
			}
			if(!config.contains("communication.port"))
			{
				config.set("communication.port", (short) 25389);
			}
			if(!config.contains("communication.requireSameProxy"))
			{
				config.set("communication.requireSameProxy", false);
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
				getProxy().getPluginManager().registerCommand(this, new CommandLobby());
				final boolean aliasTell = config.getBoolean("commands.aliasTell");
				getProxy().getPluginManager().registerCommand(this, new CommandTell(aliasTell));
				getProxy().getPluginManager().registerCommand(this, new CommandReply(aliasTell));
				getProxy().getPluginManager().registerCommand(this, new CommandList(config.getBoolean("commands.aliasList")));
				getProxy().getPluginManager().registerCommand(this, new CommandAlert());
				getProxy().getPluginManager().registerCommand(this, new CommandSend());
				final boolean aliasBan = config.getBoolean("commands.aliasBan");
				getProxy().getPluginManager().registerCommand(this, new CommandBan(aliasBan));
				getProxy().getPluginManager().registerCommand(this, new CommandUnban(aliasBan));
				getProxy().getPluginManager().registerCommand(this, new CommandEnd());
			}
			else
			{
				getLogger().log(Level.WARNING, "Please configure MultiBungeeGlue and then restart.");
			}
			getProxy().getPluginManager().registerListener(this, this);
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
			final String banReason = MultiBungeeGlue.bannedPlayers.get(hypenlessUUIDPattern.matcher(e.getLoginResult().getId()).replaceAll("$1-$2-$3-$4-$5"));
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
		final ProxiedPlayer p = e.getPlayer();
		new GluedPlayer(p);
		if(p.hasPermission("multibungeeglue.sysadmin"))
		{
			if(configured)
			{
				synchronized(connections)
				{
					synchronized(otherBungees)
					{
						if(connections.size() != otherBungees.size())
						{
							p.sendMessage(ChatMessageType.SYSTEM, new ComponentBuilder("[MultiBungeeGlue] " + connections.size() + "/" + otherBungees.size() + " peers are connected.").color(ChatColor.YELLOW).create());
						}
						else
						{
							p.sendMessage(ChatMessageType.SYSTEM, new ComponentBuilder("[MultiBungeeGlue] Everything seems alright.").color(ChatColor.GREEN).create());
						}
					}
				}
			}
			else
			{
				p.sendMessage(ChatMessageType.SYSTEM, new ComponentBuilder("Please configure MultiBungeeGlue and then restart.").color(ChatColor.RED).create());
			}
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

	static void broadcastToSysadmins(BaseComponent[] baseComponents)
	{
		for(ProxiedPlayer p : MultiBungeeGlue.instance.getProxy().getPlayers())
		{
			if(p.hasPermission("multibungeeglue.sysadmin"))
			{
				p.sendMessage(ChatMessageType.SYSTEM, baseComponents);
			}
		}
	}
}

class Connection extends Thread
{
	final String ip;
	byte workingEncryption = 0;
	private final Socket socket;
	private InputStream is;
	OutputStream os;

	Connection()
	{
		this.ip = "";
		this.workingEncryption = 2;
		this.socket = null;
		this.os = new ByteArrayOutputStream();
	}

	Connection(String ip, Socket socket, boolean initEncryption) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		this.ip = ip;
		this.socket = socket;
		this.is = socket.getInputStream();
		this.os = socket.getOutputStream();
		if(initEncryption)
		{
			final long time = System.currentTimeMillis();
			final long random = new Random().nextLong();
			this.writeLong(time);
			this.writeLong(random);
			this.flush();
			this.enableEncryption(time, random);
		}
		this.start();
	}

	private void enableEncryption(long time, long random) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		final MessageDigest md = MessageDigest.getInstance("SHA-384");
		for(int i = 7; i >= 0; i--)
		{
			md.update((byte) (time & 0xFF));
			md.update((byte) (random & 0xFF));
			time >>= 8;
			random >>= 8;
		}
		md.update((byte) Packet.values().length); // Protocol Major Version
		md.update((byte) 1); // Protocol Minor Version
		if(MultiBungeeGlue.config.getBoolean("communication.requireSameProxy"))
		{
			md.update(MultiBungeeGlue.instance.getProxy().getVersion().getBytes());
		}
		md.update(MultiBungeeGlue.config.getString("communication.sharedSecret").getBytes());
		final byte[] hash = md.digest();
		byte[] key = new byte[32];
		System.arraycopy(hash, 0, key, 0, 32);
		byte[] iv = new byte[16];
		System.arraycopy(hash, 32, iv, 0, 16);
		final SecretKey sharedKey = new SecretKeySpec(key, 0, key.length, "AES");
		Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, sharedKey, new IvParameterSpec(iv));
		is = new CipherInputStream(is, cipher);
		cipher = Cipher.getInstance("AES/CFB8/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, sharedKey, new IvParameterSpec(iv));
		os = new CipherOutputStream(os, cipher);
	}

	private void synchronize() throws IOException
	{
		MultiBungeeGlue.broadcastToSysadmins(new ComponentBuilder("[MultiBungeeGlue] Established an encryption connection to " + ip).color(ChatColor.GREEN).create());
		synchronized(MultiBungeeGlue.players)
		{
			for(GluedPlayer p : MultiBungeeGlue.players)
			{
				if(p.isLocal())
				{
					p.sendGlue(this);
				}
			}
		}
		synchronized(MultiBungeeGlue.bannedPlayers)
		{
			this.os.write(Packet.SYNCHRONIZE.ordinal());
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
			this.os.write(b);
		}
	}

	private void writeByteArray(byte[] value) throws IOException
	{
		this.writeInt(value.length);
		this.os.write(value);
	}

	void writeString(String value) throws IOException
	{
		writeByteArray(value.getBytes(StandardCharsets.UTF_8));
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
			this.os.write(b);
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

	private static byte[] readByteArray(InputStream is) throws IOException
	{
		final int length = readInt(is);
		final byte[] bytes = new byte[length];
		int i = 0;
		while(i < length)
		{
			bytes[i++] = (byte) is.read();
		}
		return bytes;
	}

	private static String readString(InputStream is) throws IOException
	{
		return new String(readByteArray(is), StandardCharsets.UTF_8);
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
			do
			{
				if(is instanceof CipherInputStream)
				{
					if(!handlePacket(is))
					{
						break;
					}
				}
				else
				{
					this.enableEncryption(readLong(is), readLong(is));
					this.workingEncryption = 1;
					this.os.write(Packet.ENCRYPTION_TEST.ordinal());
					this.writeString("Can you read this?");
					this.flush();
				}
			}
			while(!this.isInterrupted());
		}
		catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e)
		{
			e.printStackTrace();
		}
		catch(IOException ignored)
		{

		}
		finally
		{
			this.close(true);
			MultiBungeeGlue.broadcastToSysadmins(new ComponentBuilder("[MultiBungeeGlue] Lost connection to " + ip).color(ChatColor.RED).create());
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
		if(workingEncryption == 2)
		{
			if(packet == Packet.UNKNOWN)
			{
				MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Received an unknown packet (" + packetId + ") from " + (ip.equals("") ? "myself" : ip));
			}
			else
			{
				MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Received " + packet + " packet from " + (ip.equals("") ? "myself" : ip));
			}
			if(packet == Packet.SYNCHRONIZE)
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
							this.os.write(Packet.BAN_PLAYER.ordinal());
							this.writeUUID(UUID.fromString(ban.getKey()));
							this.writeString(ban.getValue());
							this.flush();
						}
					}
				}
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
			else if(packet == Packet.CHAT_MESSAGE_PLAYER)
			{
				final GluedPlayer p = GluedPlayer.get(readUUID(is));
				final String rawMessage = readString(is);
				if(p != null && p.isLocal())
				{
					p.getProxied().sendMessage(ChatMessageType.CHAT, new TextComponent(rawMessage));
				}
			}
			else if(packet == Packet.ALERT)
			{
				ProxyServer.getInstance().broadcast(TextComponent.fromLegacyText("§8[§4Alert§8]§r " + readString(is)));
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
			else if(packet == Packet.END)
			{
				ProxyServer.getInstance().stop();
			}
			else
			{
				return false;
			}
		}
		else
		{
			if(packet == Packet.ENCRYPTION_TEST)
			{
				if(this.workingEncryption == 0 && readString(is).equals("Can you read this?"))
				{
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, this.ip + " established an encrypted connection.");
					this.workingEncryption = 2;
					this.os.write(Packet.ENCRYPTION_SUCCESS.ordinal());
					this.synchronize();
					return true;
				}
			}
			else if(packet == Packet.ENCRYPTION_SUCCESS)
			{
				if(this.workingEncryption == 1)
				{
					MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Established an encrypted connection to " + this.ip + ".");
					this.workingEncryption = 2;
					this.synchronize();
					return true;
				}
			}
			MultiBungeeGlue.instance.getLogger().log(Level.INFO, this.ip + " failed to establish an encrypted connection. Make sure they're running the same version and the `communication` section in the config.yml is correct.");
			return false;
		}
		return true;
	}
}

class LoopbackConnection extends Connection
{
	LoopbackConnection()
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
				if(c.workingEncryption == 2)
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
				final Socket socket = serverSocket.accept();
				final String localIp = MultiBungeeGlue.socketAddressPattern.matcher(socket.getLocalSocketAddress().toString()).replaceAll("$1");
				final String remoteIp = MultiBungeeGlue.socketAddressPattern.matcher(socket.getRemoteSocketAddress().toString()).replaceAll("$1");
				if(localIp.equals(remoteIp))
				{
					synchronized(MultiBungeeGlue.otherBungees)
					{
						MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Dropping " + remoteIp + ", assuming that's localhost.");
						MultiBungeeGlue.otherBungees.remove(localIp);
					}
					socket.close();
				}
				else
				{
					final Connection connection = new Connection(remoteIp, socket, true);
					if(MultiBungeeGlue.config.getStringList("bungees").contains(connection.ip))
					{
						synchronized(MultiBungeeGlue.connections)
						{
							for(Connection c : MultiBungeeGlue.connections)
							{
								if(c.ip.equals(connection.ip))
								{
									if(c.workingEncryption == 2)
									{
										MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Denied connection from " + connection.ip + " because we already have a connection with them.");
										connection.close(true);
									}
									else
									{
										c.close(true);
									}
									break;
								}
							}
							if(connection.isAlive())
							{
								MultiBungeeGlue.connections.add(connection);
							}
						}
					}
					else
					{
						MultiBungeeGlue.instance.getLogger().log(Level.INFO, "Denied connection from " + connection.ip + ". If this is one of your servers, make sure to update the `bungees` section of the config.yml.");
						connection.close(false);
					}
				}
			}
			catch(IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e)
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
				final ArrayList<String> missingPeers;
				synchronized(MultiBungeeGlue.otherBungees)
				{
					missingPeers = new ArrayList<>(MultiBungeeGlue.otherBungees);
				}
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
							MultiBungeeGlue.connections.add(new Connection(ip, new Socket(ip, MultiBungeeGlue.config.getShort("communication.port")), false));
						}
					}
					catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | UnknownHostException e)
					{
						e.printStackTrace();
					}
					catch(IOException ignored)
					{
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
	ENCRYPTION_TEST,
	ENCRYPTION_SUCCESS,
	SYNCHRONIZE,
	GLUE_PLAYER,
	UNGLUE_PLAYER,
	CHAT_MESSAGE_PLAYER,
	ALERT,
	SEND_ALL,
	SEND_SERVER,
	SEND_PLAYER,
	BAN_PLAYER,
	UNBAN_PLAYER,
	END;

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
	String lastTold;

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
					p.getProxied().disconnect(new ComponentBuilder("You logged in from a different location.").color(ChatColor.RED).create());
				}
				MultiBungeeGlue.players.remove(p);
			}
			MultiBungeeGlue.players.add(this);
		}
	}

	void sendGlue(Connection c) throws IOException
	{
		c.os.write(Packet.GLUE_PLAYER.ordinal());
		c.writeUUID(uuid);
		c.writeString(name);
		c.os.write((unbannable ? 1 : 0));
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
					c.os.write(Packet.UNGLUE_PLAYER.ordinal());
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

	Connection getConnection()
	{
		if(!isLocal())
		{
			synchronized(MultiBungeeGlue.connections)
			{
				for(Connection c : MultiBungeeGlue.connections)
				{
					if(c.ip.equals(this.proxy))
					{
						return c;
					}
				}
			}
		}
		return MultiBungeeGlue.loopback;
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

class CommandLobby extends Command
{
	CommandLobby()
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

class CommandTell extends Command
{
	CommandTell(boolean aliasTell)
	{
		super("mtell", "multibungeeglue.command.tell", aliasTell ? new String[]{"mwhisper", "mmsg", "mw", "tell", "msg", "whisper", "w"} : new String[]{"mwhisper", "mmsg", "mw"});
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		if(args.length > 1)
		{
			final GluedPlayer p = GluedPlayer.get(args[0]);
			if(p == null)
			{
				s.sendMessage(new ComponentBuilder("Couldn't find " + args[0]).color(ChatColor.RED).create());
				return;
			}
			final StringBuilder builder = new StringBuilder(args[1]);
			if(args.length > 2)
			{
				for(int i = 2; i < args.length; i++)
				{
					builder.append(" ").append(args[i]);
				}
			}
			final String message = builder.toString();
			try
			{
				s.sendMessage(new TextComponent(MultiBungeeGlue.config.getString("commands.tellSent").replace("%recipient%", p.name).replace("%message%", message)));
				final Connection c = p.getConnection();
				c.os.write(Packet.CHAT_MESSAGE_PLAYER.ordinal());
				c.writeUUID(p.uuid);
				c.writeString(MultiBungeeGlue.config.getString("commands.tellReceived").replace("%sender%", s.getName()).replace("%message%", message));
				c.flush();
				if(s instanceof ProxiedPlayer)
				{
					synchronized(MultiBungeeGlue.players)
					{
						final GluedPlayer _p = GluedPlayer.get(((ProxiedPlayer) s).getUniqueId());
						if(_p != null)
						{
							_p.lastTold = p.name;
						}
						else
						{
							MultiBungeeGlue.instance.getLogger().log(Level.WARNING, s.getName() + " was not found in players list");
						}
					}
				}
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /" + (MultiBungeeGlue.config.getBoolean("commands.aliasTell") ? "" : "m") + "tell <player> <message>").color(ChatColor.RED).create());
		}
	}
}

class CommandReply extends Command
{
	CommandReply(boolean aliasTell)
	{
		super("mreply", "multibungeeglue.command.tell", aliasTell ? new String[]{"mr", "reply", "r"} : new String[]{"mr"});
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		if(s instanceof ProxiedPlayer)
		{
			if(args.length == 0)
			{
				s.sendMessage(new ComponentBuilder("Syntax: /" + (MultiBungeeGlue.config.getBoolean("commands.aliasTell") ? "" : "m") + "reply <message>").color(ChatColor.RED).create());
				return;
			}
			//noinspection ConstantConditions
			final String lastTold = GluedPlayer.get(((ProxiedPlayer) s).getUniqueId()).lastTold;
			if(lastTold == null)
			{
				s.sendMessage(new ComponentBuilder("You didn't message anyone recently. Use /" + (MultiBungeeGlue.config.getBoolean("commands.aliasTell") ? "" : "m") + "tell first.").color(ChatColor.RED).create());
				return;
			}
			final GluedPlayer p = GluedPlayer.get(lastTold);
			if(p == null)
			{
				s.sendMessage(new ComponentBuilder(lastTold + " isn't online anymore.").color(ChatColor.RED).create());
				return;
			}
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
				s.sendMessage(new TextComponent(MultiBungeeGlue.config.getString("commands.tellSent").replace("%recipient%", p.name).replace("%message%", message)));
				final Connection c = p.getConnection();
				c.os.write(Packet.CHAT_MESSAGE_PLAYER.ordinal());
				c.writeUUID(p.uuid);
				c.writeString(MultiBungeeGlue.config.getString("commands.tellReceived").replace("%sender%", s.getName()).replace("%message%", message));
				c.flush();
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("This command is only for players.").color(ChatColor.RED).create());
		}
	}
}

class CommandList extends Command
{
	CommandList(boolean aliasList)
	{
		super("mlist", "multibungeeglue.command.list", aliasList ? new String[]{"list"} : new String[0]);
	}

	@Override
	public void execute(CommandSender s, String[] args)
	{
		synchronized(MultiBungeeGlue.players)
		{
			if(MultiBungeeGlue.players.size() == 0 || MultiBungeeGlue.players.size() > 50)
			{
				s.sendMessage(new TextComponent("There are " + MultiBungeeGlue.players.size() + " players on this network."));
			}
			else
			{
				if(MultiBungeeGlue.players.size() == 1)
				{
					s.sendMessage(new TextComponent("There is 1 player on this network:"));
				}
				else
				{
					s.sendMessage(new TextComponent("There are " + MultiBungeeGlue.players.size() + " players on this network:"));
				}
				for(GluedPlayer p : MultiBungeeGlue.players)
				{
					s.sendMessage(new TextComponent(p.name));
				}
			}
		}
	}
}

class CommandAlert extends Command
{
	CommandAlert()
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
				MultiBungeeGlue.broadcaster.os.write(Packet.ALERT.ordinal());
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

class CommandSend extends Command
{
	CommandSend()
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
					MultiBungeeGlue.broadcaster.os.write(Packet.SEND_ALL.ordinal());
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
						MultiBungeeGlue.broadcaster.os.write(Packet.SEND_SERVER.ordinal());
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
						try
						{
							final Connection c = p.getConnection();
							c.os.write(Packet.SEND_PLAYER.ordinal());
							c.writeString(args[0]);
							c.writeString(args[1]);
							c.flush();
						}
						catch(IOException e)
						{
							e.printStackTrace();
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

class CommandBan extends Command
{
	CommandBan(boolean aliasBan)
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
				return;
			}
			if(p.unbannable)
			{
				s.sendMessage(new ComponentBuilder(p.name + " is unbannable.").color(ChatColor.RED).create());
				return;
			}
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
				MultiBungeeGlue.broadcaster.os.write(Packet.BAN_PLAYER.ordinal());
				MultiBungeeGlue.broadcaster.writeUUID(p.uuid);
				MultiBungeeGlue.broadcaster.writeString(reason);
				MultiBungeeGlue.broadcaster.flush();
			}
			catch(IOException e)
			{
				e.printStackTrace();
			}
		}
		else
		{
			s.sendMessage(new ComponentBuilder("Syntax: /" + (MultiBungeeGlue.config.getBoolean("commands.aliasBan") ? "" : "m") + "ban <player> [reason]").color(ChatColor.RED).create());
		}
	}
}

class CommandUnban extends Command
{
	CommandUnban(boolean aliasBan)
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
				MultiBungeeGlue.broadcaster.os.write(Packet.UNBAN_PLAYER.ordinal());
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
			s.sendMessage(new ComponentBuilder("Syntax: /" + (MultiBungeeGlue.config.getBoolean("commands.aliasBan") ? "" : "m") + "unban <uuid>").color(ChatColor.RED).create());
		}
	}
}

class CommandEnd extends Command
{
	CommandEnd()
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
					c.os.write(Packet.END.ordinal());
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
