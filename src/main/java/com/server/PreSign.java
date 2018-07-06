package com.server;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;

public class PreSign extends HttpServlet{
    public static final String SRC = "test.pdf";

    private String message;

    public void init() throws ServletException
    {
        message = "Pre Sign New";
    }

    public void doGet(HttpServletRequest req,
                      HttpServletResponse resp)
            throws ServletException, IOException
    {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        out.println("<h1>" + message + "</h1>");
        out.println("<h1>" + System.getProperty("user.dir") + "</h1>");
        out.println("<h1>" + df.format(new Date()) + "</h1>");
    }

    public void doPost(HttpServletRequest req,
                       HttpServletResponse resp) throws IOException {
        resp.setContentType("application/octet-stream");
        try {
            // We get the self-signed certificate from the client
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate[] chain = new Certificate[1];
            chain[0] = factory.generateCertificate(req.getInputStream());

            // we create a reader and a stamper
            PdfReader reader = new PdfReader(SRC);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');

            // we create the signature appearance
            PdfSignatureAppearance sap = stamper.getSignatureAppearance();
            sap.setReason("Test");
            sap.setLocation("On a server!");
            sap.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
            sap.setCertificate(chain[0]);

            // we create the signature infrastructure
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            dic.setReason(sap.getReason());
            dic.setLocation(sap.getLocation());
            dic.setContact(sap.getContact());
            dic.setDate(new PdfDate(sap.getSignDate()));
            sap.setCryptoDictionary(dic);
            HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
            exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
            sap.preClose(exc);
            ExternalDigest externalDigest = new ExternalDigest() {
                public MessageDigest getMessageDigest(String hashAlgorithm)
                        throws GeneralSecurityException {
                    return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
                }
            };
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
            InputStream data = sap.getRangeStream();
            byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));

            // we get OCSP and CRL for the cert
            OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
            OcspClient ocspClient = new OcspClientBouncyCastle(ocspVerifier);
            byte[] ocsp = null;
            if (chain.length >= 2 && ocspClient != null) {
                ocsp = ocspClient.getEncoded((X509Certificate) chain[0], (X509Certificate) chain[1], null);
            }
            Collection<byte[]> crlBytes = null;

            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);

            // We store the objects we'll need for post signing in a session
            HttpSession session = req.getSession(true);
            session.setAttribute("sgn", sgn);
            session.setAttribute("hash", hash);
            session.setAttribute("ocsp", ocsp);
            session.setAttribute("sap", sap);
            session.setAttribute("baos", baos);

            // we write the hash that needs to be signed to the HttpResponse output
            OutputStream os = resp.getOutputStream();
            os.write(sh, 0, sh.length);
            os.flush();
            os.close();

        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        } catch (DocumentException e) {
            throw new IOException(e);
        }

    }

    public void destroy()
    {

    }
}
