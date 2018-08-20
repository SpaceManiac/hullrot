-- Example Hullrot controller for "Trouble in Terrorist Town", a GMOD gamemode.

if GetConVarString("gamemode") == "terrortown" and SERVER then
	require "bromsock"

	-- Set up cvars.
	if not ConVarExists("hullrot_enabled") then CreateConVar("hullrot_enabled", "1") end
	if not ConVarExists("hullrot_verbose") then CreateConVar("hullrot_verbose", "0") end

	-- Connect to Hullrot control on server startup.
	local function InitPostEntity()
		print(_VERSION)
		print("Hullrot initialized")
		netclient = BromSock()
		netclient:Connect("localhost", 10961)
	end

	local function sendPacket(data)
		-- Hullrot client protocol implementation:
		-- Encode the message as JSON.
		local json = util.TableToJSON(data)
		if hullrot_verbose then
			print(json)
		end
		-- Calculate the length of the JSON message.
		local slen = string.len(json)
		local packet = BromPacket()
		-- Write the length as a big-endian unsigned 32-bit number.
		packet:WriteByte(bit.rshift(slen,24))
		packet:WriteByte(bit.band(bit.rshift(slen,16), 0xff))
		packet:WriteByte(bit.band(bit.rshift(slen,8) , 0xff))
		packet:WriteByte(bit.band(slen, 0xff))
		-- Write the JSON itself.
		packet:WriteStringRaw(json)
		-- Transmit the packet.
		netclient:Send(packet, true)
	end

	local function setAlive(ply)
		-- Alive players are always speaking on the living channel.
		local name = string.lower(ply:GetName())
		sendPacket {
			PatchMobState = {
				ckey = name,
				hear_freqs = { 1 },
				hot_freqs = { 1 },
			}
		}
	end

	local function setDead(ply)
		-- Dead players can hear both channels, but only speak to other dead.
		local name = string.lower(ply:GetName())
		sendPacket {
			PatchMobState = {
				ckey = name,
				hear_freqs = { 1, 2 },
				hot_freqs = { 2 },
			}
		}
	end

	local function TTTPrepareRound()
		-- The round is setting up, we are not yet playing.
		sendPacket {
			Playing = false
		}
	end

	local function PlayerInitialSpawn(ply)
		-- Players who join are considered dead.
		setDead(ply)
	end

	local function TTTBeginRound()
		-- Set alive players to alive and spectators to dead.
		for key, ply in pairs(player.GetHumans()) do
			print(key, ply)
			if ply:IsSpec() then
				setDead(ply)
			else
				setAlive(ply)
			end
		end
		-- The round has started, we are now playing.
		sendPacket {
			Playing = true
		}
	end

	local function TTTEndRound(result)
		-- The round has ended, we are no longer playing.
		sendPacket {
			Playing = false
		}
	end

	local function Hullrot_CheckForWin()
		if GAMEMODE.MapWin == WIN_TRAITOR or GAMEMODE.MapWin == WIN_INNOCENT then
			local mw = GAMEMODE.MapWin
			GAMEMODE.MapWin = WIN_NONE
			return mw
		end

		local traitor_alive = false
		local innocent_alive = false
		for k, v in pairs(player.GetAll()) do
			if v:Alive() and v:IsTerror() then
				if v:GetTraitor() then
					traitor_alive = true
				else
					innocent_alive = true
				end
			end

			if traitor_alive and innocent_alive then
				-- Early out.
				return WIN_NONE
			end
		end

		if traitor_alive and not innocent_alive then
			return WIN_TRAITOR
		elseif not traitor_alive and innocent_alive then
			return WIN_INNOCENT
		elseif not innocent_alive then
			-- Ultimately if no one is alive, traitors win.
			return WIN_TRAITOR
		end

		return WIN_NONE
	end

	local function PlayerDeath(victim, inflictor, attacker)
		setDead(victim)
		-- Fast path to turn on all-talk as soon as the last player dies,
		-- rather than waiting for the round to end formally in a few seconds.
		timer.Simple(0.005, function()
			if GetRoundState() == ROUND_ACTIVE && Hullrot_CheckForWin() != WIN_NONE then
				sendPacket {
					Playing = false
				}
			end
		end)
	end

	-- Debugging command
	concommand.Add("hullrot_fix", function(ply, cmd, args, argStr)
		for key, ply in pairs(player.GetHumans()) do
			print(key, ply)
			if ply:IsSpec() then
				setDead(ply)
			else
				setAlive(ply)
			end
		end
	end)

	-- Register hooks.
	hook.Add("InitPostEntity", "hullrot_init", InitPostEntity)
	hook.Add("TTTPrepareRound", "hullrot_prepare", TTTPrepareRound)
	hook.Add("PlayerInitialSpawn", "hullrot_playerInit", PlayerInitialSpawn)
	hook.Add("TTTBeginRound", "hullrot_begin", TTTBeginRound)
	hook.Add("PlayerDeath", "hullrot_death", PlayerDeath)
	hook.Add("TTTEndRound", "hullrot_end", TTTEndRound)
end
