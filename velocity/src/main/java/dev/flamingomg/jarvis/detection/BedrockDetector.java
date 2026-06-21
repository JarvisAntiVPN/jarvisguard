package dev.flamingomg.jarvis.detection;

import com.velocitypowered.api.proxy.ProxyServer;
import dev.flamingomg.jarvis.config.ConfigManager;
import org.geysermc.floodgate.api.FloodgateApi;
import org.slf4j.Logger;

import java.util.UUID;

public final class BedrockDetector {

    private final ConfigManager config;
    private final boolean floodgatePresent;

    public BedrockDetector(ProxyServer proxy, ConfigManager config, Logger logger) {
        this.config = config;
        this.floodgatePresent = proxy.getPluginManager().getPlugin("floodgate").isPresent();
        if (floodgatePresent) {
            logger.debug("Floodgate detected: Bedrock player protection active.");
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
