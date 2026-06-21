package dev.flamingomg.jarvis.detection;

import net.md_5.bungee.api.ProxyServer;
import dev.flamingomg.jarvis.config.ConfigManager;
import org.geysermc.floodgate.api.FloodgateApi;
import java.util.logging.Logger;

import java.util.UUID;

public final class BedrockDetector {

    private final ConfigManager config;
    private final boolean floodgatePresent;

    public BedrockDetector(ProxyServer proxy, ConfigManager config, Logger logger) {
        this.config = config;
        this.floodgatePresent = proxy.getPluginManager().getPlugin("floodgate") != null;
        if (floodgatePresent) {
            logger.fine("Floodgate detected: Bedrock player protection active.");
        }
    }

    public boolean isBedrockUsername(String username) {
        if (!floodgatePresent || username == null) {
            return false;
        }
        String prefix = config.getString("floodgate.username-prefix", ".");
        return !prefix.isEmpty() && username.startsWith(prefix);
    }

    public boolean isBedrockPlayer(UUID uuid) {
        if (!floodgatePresent) {
            return false;
        }
        try {
            return FloodgateApi.getInstance().isFloodgatePlayer(uuid);
        } catch (Throwable t) {
            return false;
        }
    }

    public boolean isFloodgatePresent() {
        return floodgatePresent;
    }
}
