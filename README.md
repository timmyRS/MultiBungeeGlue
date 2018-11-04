# MultiBungeeGlue

The database-free glue for multi-BungeeCord networks.

**Note:** MultiBungeeGlue is still in development, which means there is very verbose logging, including stack traces of irrelevant exceptions.

- [Download](https://raw.githubusercontent.com/timmyrs/MultiBungeeGlue/master/MultiBungeeGlue.jar)

## Installation

For each BungeeCord server:

1. Move the `MultiBungeeGlue.jar` into the `plugins/` folder.
2. Restart BungeeCord.
3. Edit the `plugins/MultiBungeeGlue/config.yml`.
4. Restart BungeeCord again.

## Permissions

Permission | Description
-----------|-----------
`multibungeeglue.command.lobby` | Allows the player to execute `/lobby`.
`multibungeeglue.command.alert` | Allows the player to execute `/malert`.
`multibungeeglue.command.send` | Allows the player to execute `/msend`.
`multibungeeglue.command.ban` | Allows the player to execute `/mban`.
`multibungeeglue.command.unban` | Allows the player to execute `/munban`.
`multibungeeglue.unbannable` | Allows the player to not be banned.
`multibungeeglue.command.end` | Allows the player to execute `/mend`.

## Commands

### `/lobby`

**Alias:** `/hub`

Connects the player to the lobby server as defined by `commands.lobbyServer` in the `config.yml`.

### `/malert <message>`

Sends an alert to every player.

You can also use `/alert` if the `cmd_alert` module is removed.

### `/msend <all|server|player> <target server>`

Sends every player, or everyone on `server`, or the player `player` to `target server`.

You can also use `/send` if the `cmd_send` module is removed.


### `/mban <player> [reason]`

Bans the given player with an optional reason.

You can also use `/ban` if `commands.aliasBan` is set to `true` in the `config.yml`.

### `/munban <uuid>`

**Alias:** `/mpardon`

Bans the given player with an optional reason.

You can also use `/unban` and `/pardon` if `commands.aliasBan` is set to `true` in the `config.yml`.

### `/mend`

Stops all BungeeCord servers (or restarts them if they're running inside a loop).
