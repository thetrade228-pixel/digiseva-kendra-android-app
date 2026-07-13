package in.digisevakendra.app;

import android.os.Bundle;
import android.webkit.WebView;
import android.widget.Toast;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

    private long backPressedTime = 0;
    private Toast backToast;

    // ✅ Extra visual gap between the phone's status bar (time/wifi/battery)
    //    and the app's own header, so they never look cramped/touching —
    //    purely cosmetic breathing room on top of the real inset value.
    private static final int EXTRA_TOP_GAP_DP = 14;

    private int dpToPx(int dp) {
        return Math.round(dp * getResources().getDisplayMetrics().density);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        WebView webView = this.getBridge().getWebView();
        // Remove the browser-like blue overscroll glow so it feels like a native app
        webView.setOverScrollMode(WebView.OVER_SCROLL_NEVER);

        // We deliberately do NOT fight edge-to-edge here (Capacitor's own StatusBar
        // plugin, and Android 15+/SDK 35+ itself, both force it anyway — fighting
        // it with setDecorFitsSystemWindows(true) was the previous bug).
        // Instead: let edge-to-edge happen, and manually pad the WebView by
        // exactly the system bar heights so content never sits under them.
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);

        // 1) Immediate fallback padding using the classic Android resource
        //    dimensions — applied right away so there's never a frame where
        //    content is unpadded, even before any inset event fires.
        int fallbackTop = getStatusBarHeightPx() + dpToPx(EXTRA_TOP_GAP_DP);
        int fallbackBottom = getNavBarHeightPx();
        webView.setPadding(0, fallbackTop, 0, fallbackBottom);

        // 2) Precise padding via the modern WindowInsets API — overrides the
        //    fallback with the exact real value as soon as it's available.
        //    We combine systemBars() AND displayCutout() (needed for notch /
        //    waterdrop-cutout phones) and use whichever is larger for the top.
        ViewCompat.setOnApplyWindowInsetsListener(webView, (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            Insets cutout = insets.getInsets(WindowInsetsCompat.Type.displayCutout());
            int top = Math.max(systemBars.top, cutout.top) + dpToPx(EXTRA_TOP_GAP_DP);
            int bottom = Math.max(systemBars.bottom, cutout.bottom);
            int left = Math.max(systemBars.left, cutout.left);
            int right = Math.max(systemBars.right, cutout.right);
            v.setPadding(left, top, right, bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(webView);
    }

    private int getStatusBarHeightPx() {
        int id = getResources().getIdentifier("status_bar_height", "dimen", "android");
        return id > 0 ? getResources().getDimensionPixelSize(id) : Math.round(24 * getResources().getDisplayMetrics().density);
    }

    private int getNavBarHeightPx() {
        int id = getResources().getIdentifier("navigation_bar_height", "dimen", "android");
        return id > 0 ? getResources().getDimensionPixelSize(id) : 0;
    }

    @Override
    public void onBackPressed() {
        WebView webView = this.getBridge().getWebView();
        // If there is web history (e.g. moved from login to dashboard), go back inside the app
        if (webView.canGoBack()) {
            webView.goBack();
            return;
        }

        // On the app's home screen, require a second back-press to exit (native app behavior)
        if (backPressedTime + 2000 > System.currentTimeMillis()) {
            if (backToast != null) backToast.cancel();
            super.onBackPressed();
            return;
        } else {
            backToast = Toast.makeText(this, "Exit karne ke liye dobara back dabayein", Toast.LENGTH_SHORT);
            backToast.show();
        }
        backPressedTime = System.currentTimeMillis();
    }
}
