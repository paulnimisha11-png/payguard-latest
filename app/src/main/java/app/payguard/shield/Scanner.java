package app.payguard.shield;

import android.app.Activity;
import android.widget.Toast;

import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanner;
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning;

/** Full-screen QR scanner provided by Google Play services (no camera permission needed in this app). */
public final class Scanner {
    private Scanner() {}

    public interface Result {
        void onText(String text);
    }

    public static void scan(Activity a, Result cb) {
        GmsBarcodeScannerOptions options = new GmsBarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .build();
        GmsBarcodeScanner scanner = GmsBarcodeScanning.getClient(a, options);
        scanner.startScan()
                .addOnSuccessListener(barcode -> {
                    String raw = barcode.getRawValue();
                    if (raw != null && !raw.trim().isEmpty()) cb.onText(raw.trim());
                    else Toast.makeText(a, R.string.scan_empty, Toast.LENGTH_SHORT).show();
                })
                .addOnFailureListener(e -> Toast.makeText(a, a.getString(R.string.scan_failed), Toast.LENGTH_LONG).show());
    }
}
