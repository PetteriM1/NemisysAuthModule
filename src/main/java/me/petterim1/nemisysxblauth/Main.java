package me.petterim1.nemisysxblauth;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.event.EventHandler;
import org.itxtech.nemisys.event.Listener;
import org.itxtech.nemisys.event.server.DataPacketReceiveEvent;
import org.itxtech.nemisys.network.protocol.mcpe.DisconnectPacket;
import org.itxtech.nemisys.network.protocol.mcpe.LoginPacket;
import org.itxtech.nemisys.plugin.PluginBase;
import org.itxtech.nemisys.utils.BinaryStream;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class Main extends PluginBase implements Listener {

    private static final Gson GSON = new Gson();

    private static final String MOJANG_PUBLIC_KEY_BASE64 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8ELkixyLcwlZryUQcu1TvPOmI2B7vX83ndnWRUaXm74wFfa5f/lwQNTfrLVHa2PmenpGI6JhIMUJaWZrjmMj90NoKNFSNBuKdm8rYiXsfaz3K36x/1U26HpG0ZxK/V1V";
    private static final PublicKey MOJANG_PUBLIC_KEY;

    static {
        try {
            MOJANG_PUBLIC_KEY = generateKey(MOJANG_PUBLIC_KEY_BASE64);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private static PublicKey generateKey(String base64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    @Override
    public void onEnable() {
        getServer().getPluginManager().registerEvents(this, this);
    }

    @EventHandler(ignoreCancelled = true)
    public void receiveDataPacket(DataPacketReceiveEvent e) {
        if (e.getPacket() instanceof LoginPacket) {
            try {
                if (auth((LoginPacket) e.getPacket())) {
                    return;
                }
            } catch (Exception ignore) {
            }
            Player p = e.getPlayer();
            e.setCancelled(true);
            p.close("Not authenticated", false);
            DisconnectPacket pk = new DisconnectPacket();
            pk.hideDisconnectionScreen = false;
            pk.message = "disconnectionScreen.notAuthenticated";
            p.sendDataPacket(pk, true);
            //p.getServer().getNetwork().blockAddress(p.getSocketAddress().getAddress(), 5);
            //p.getServer().getLogger().notice("Blocked " + p.getAddress() + " for 5 seconds due to failed Xbox auth");
        }
    }

    private static boolean auth(LoginPacket pk) {
        BinaryStream bs = new BinaryStream();
        bs.setBuffer(pk.getBuffer(), 0);
        int length = bs.getLInt();
        if (length > 3000000) return false;
        Map<String, List<String>> map = GSON.fromJson(new String(bs.get(length), StandardCharsets.UTF_8), new MapTypeToken().getType());
        if (map.isEmpty() || !map.containsKey("chain") || map.get("chain").isEmpty()) return false;
        return verifyChain(map.get("chain"));
    }

    private static boolean verifyChain(List<String> chains) {
        PublicKey lastKey = null;
        boolean mojangKeyVerified = false;
        for (String chain: chains) {
            JWSObject jws;
            try {
                jws = JWSObject.parse(chain);
            } catch (ParseException e) {
                return false;
            }
            if (!mojangKeyVerified) {
                mojangKeyVerified = verify(MOJANG_PUBLIC_KEY, jws);
            }
            if (lastKey != null) {
                if (!verify(lastKey, jws)) {
                    return false;
                }
            }
            String base64key = jws.getPayload().toJSONObject().getAsString("identityPublicKey");
            if (base64key == null) {
                return false;
            }
            try {
                lastKey = generateKey(base64key);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                return false;
            }
        }
        return mojangKeyVerified;
    }

    private static boolean verify(PublicKey key, JWSObject object) {
        try {
            return object.verify(new DefaultJWSVerifierFactory().createJWSVerifier(object.getHeader(), key));
        } catch (JOSEException e) {
            return false;
        }
    }

    private static class MapTypeToken extends TypeToken<Map<String, List<String>>> {
    }
}
