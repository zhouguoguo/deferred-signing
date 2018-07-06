package com.server;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;

public class PostSign extends HttpServlet{
    private String message;

    public void init() throws ServletException
    {
        message = "Post Sign";
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
        // we get the objects we need for postsigning from the session
        HttpSession session = req.getSession(false);
        PdfPKCS7 sgn = (PdfPKCS7) session.getAttribute("sgn");
        byte[] hash = (byte[]) session.getAttribute("hash");
        byte[] ocsp = (byte[]) session.getAttribute("ocsp");
        PdfSignatureAppearance sap = (PdfSignatureAppearance) session.getAttribute("sap");
        ByteArrayOutputStream os = (ByteArrayOutputStream) session.getAttribute("baos");
        session.invalidate();

        // we read the signed bytes
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = req.getInputStream();
        int read;
        byte[] data = new byte[256];
        while ((read = is.read(data, 0, data.length)) != -1) {
            baos.write(data, 0, read);
        }

        // we complete the PDF signing process
        sgn.setExternalDigest(baos.toByteArray(), null, "RSA");
        Collection<byte[]> crlBytes = null;
        TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle("http://timestamp.gdca.com.cn/tsa", null, null);
        byte[] encodedSig = sgn.getEncodedPKCS7(hash, tsaClient, ocsp, crlBytes, MakeSignature.CryptoStandard.CMS);
        byte[] paddedSig = new byte[8192];
        System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));

        try {
            sap.close(dic2);
        } catch (DocumentException e) {
            throw new IOException(e);
        }
        byte[] pdf = os.toByteArray();
        OutputStream sos = resp.getOutputStream();
        sos.write(pdf, 0, pdf.length);
        sos.flush();
        sos.close();

    }
}
