package com.treeke.asst.service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.net.URL;

public class ImageKit {

    private static final int COLOR = (0xFF << 24) | (128 << 16) | (128 << 8) | 128;

    public static int getXpos(String slideID, int ypos) {
        String urlPath = "https://asst.cetccloud.com/oort/oortcloud-sso/slide/v1/" + slideID + "/big.png";
        ypos += 10;
        try {
            URL url = new URL(urlPath);
            BufferedImage image = ImageIO.read(url);
            for (int xpos = 38; xpos < 260; xpos++) {
                if (COLOR == image.getRGB(xpos, ypos)) {
                    return xpos - 2;
                }
            }
        } catch (Exception e) {

        }
        return -1;
    }

}
