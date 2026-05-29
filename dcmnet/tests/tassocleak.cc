/*
 *
 *  Copyright (C) 2026, OFFIS e.V.
 *  All rights reserved.  See COPYRIGHT file for details.
 *
 *  This software and supporting documentation were developed by
 *
 *    OFFIS e.V.
 *    R&D Division Health
 *    Escherweg 2
 *    D-26121 Oldenburg, Germany
 *
 *
 *  Module:  dcmnet
 *
 *  Author:  Michael Onken
 *
 *  Purpose: Integration regression tests that drive an in-process DcmSCP with
 *           hand-crafted A-ASSOCIATE-RQ PDUs. They exercise the receiver-side
 *           association request handling on malformed input that a conformant
 *           DCMTK requestor (DcmSCU / the ASC_* API) would refuse to put on
 *           the wire. Built with DCMTK_WITH_SANITIZERS=ON these tests double
 *           as memory-error / leak regression tests for the DUL association
 *           parsing and translation code paths.
 *
 */


#include "dcmtk/config/osconfig.h"    /* make sure OS specific configuration is included first */

#ifdef WITH_THREADS

#include "dcmtk/ofstd/oftest.h"
#include "dcmtk/ofstd/ofstd.h"        /* for OFStandard::initializeNetwork() */
#include "dcmtk/ofstd/ofthread.h"     /* for OFThread */
#include "dcmtk/dcmnet/scp.h"
#include "dcmtk/dcmnet/dcmtrans.h"    /* for DcmTCPConnection */
#include "dcmtk/dcmnet/dcompat.h"     /* for platform socket headers */
#include "dcmtk/dcmnet/dulstruc.h"    /* DUL_TYPE* constants, DUL_PROTOCOL */
#include "dcmtk/dcmnet/dul.h"


/* --------------------------------------------------------------------------
 *  Minimal in-process SCP that accepts exactly one association attempt and
 *  then returns. The DUL state machine (and therefore the association request
 *  parsing/translation) runs inside ASC_receiveAssociation() before the SCP
 *  gets a chance to accept or reject, so it suffices to let the SCP try to
 *  receive a single association.
 * ------------------------------------------------------------------------ */
struct OneShotReceiverSCP : DcmSCP, OFThread
{
    OneShotReceiverSCP()
        : DcmSCP()
        , m_listen_result(EC_NotYetImplemented)
        , m_portNum(0)
    {
        DcmSCPConfig& config = getConfig();
        config.setAETitle("RECV_SCP");
        // Non-blocking accept with a short connection timeout, so the accept
        // loop cannot get stuck if a (future) malformed PDU leaves the SCP
        // waiting on a partial read, or if no client connects at all. For the
        // normal flow the client connects immediately, so this timeout is not
        // hit and adds no delay.
        config.setConnectionBlockingMode(DUL_NOBLOCK);
        config.setConnectionTimeout(2 /* seconds */);
        config.setHostLookupEnabled(OFFalse);
        config.setPort(0); // OS chooses a free port
        OFList<OFString> xfers;
        xfers.push_back(UID_LittleEndianImplicitTransferSyntax);
        OFCHECK(config.addPresentationContext(UID_VerificationSOPClass, xfers).good());
        OFCHECK(openListenPort().good());
        m_portNum = config.getPort();
    }

    /** Stop the accept loop after the single association attempt has been
     *  handled, so the SCP thread returns and can be joined.
     */
    virtual OFBool stopAfterCurrentAssociation()
    {
        return OFTrue;
    }

    /** Also stop if the connection timeout elapses without any association
     *  request. Together with the non-blocking mode above this guarantees the
     *  accept loop terminates even if no client ever connects, so a stuck test
     *  fails fast (via join()) instead of hanging.
     */
    virtual OFBool stopAfterConnectionTimeout()
    {
        return OFTrue;
    }

    virtual void run()
    {
        m_listen_result = acceptAssociations();
    }

    OFCondition m_listen_result;
    Uint16 m_portNum;
};


/* Write a 16-bit big-endian value into buf and advance the cursor. */
static void put_u16_be(unsigned char *&p, unsigned short v)
{
    *p++ = OFstatic_cast(unsigned char, (v >> 8) & 0xff);
    *p++ = OFstatic_cast(unsigned char, v & 0xff);
}

/* Write a 32-bit big-endian value into buf and advance the cursor. */
static void put_u32_be(unsigned char *&p, unsigned long v)
{
    *p++ = OFstatic_cast(unsigned char, (v >> 24) & 0xff);
    *p++ = OFstatic_cast(unsigned char, (v >> 16) & 0xff);
    *p++ = OFstatic_cast(unsigned char, (v >> 8) & 0xff);
    *p++ = OFstatic_cast(unsigned char, v & 0xff);
}

/* Write a sub-item header (type + reserved + 2-byte big-endian length) and
 * advance the cursor. */
static void put_subitem_header(unsigned char *&p, unsigned char type, unsigned short bodyLen)
{
    *p++ = type;
    *p++ = 0x00;
    put_u16_be(p, bodyLen);
}


/* Open a blocking TCP connection to 127.0.0.1:port. Sending and
 * tearing the connection down is done via DcmTCPConnection so the test needs
 * no platform-specific socket code. Returns an invalid socket on failure. */
static DcmNativeSocketType connect_loopback(Uint16 port)
{
    DcmNativeSocketType sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == OFstatic_cast(DcmNativeSocketType, -1))
        return sock;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, OFreinterpret_cast(struct sockaddr*, &addr), sizeof(addr)) != 0)
        return OFstatic_cast(DcmNativeSocketType, -1);
    return sock;
}


/* Build an A-ASSOCIATE-RQ PDU whose single presentation context contains an
 * Abstract Syntax sub-item (Verification SOP Class) but NO Transfer Syntax
 * sub-items. The PDU is otherwise well-formed: Application Context item +
 * User Information item with Maximum Length and Implementation Class UID
 * sub-items.
 *
 * We cannot use the existing C++/C API to construct this since in DCMTK
 * it is protected not to run any Presentation Contexts with 0 transfer
 * syntaxes.
 *
 * @param  outLen  receives the total PDU length on the wire (incl. preamble)
 * @return heap-allocated buffer (caller frees with delete[])
 */
static unsigned char* build_zero_ts_assoc_rq(unsigned long &outLen)
{
    const char *appCtx       = "1.2.840.10008.3.1.1.1";  // DICOM Application Context
    const char *abstractStx  = "1.2.840.10008.1.1";      // Verification SOP Class
    const char *implClassUID = "1.2.276.0.7230010.3.0.3.6.0"; // random digits

    const unsigned short appCtxLen   = OFstatic_cast(unsigned short, strlen(appCtx));
    const unsigned short abstractLen = OFstatic_cast(unsigned short, strlen(abstractStx));
    const unsigned short implLen     = OFstatic_cast(unsigned short, strlen(implClassUID));

    // Sub-PDU sizes (4-byte header + body).
    const unsigned long appCtxItem    = 4 + appCtxLen;
    const unsigned long abstractItem  = 4 + abstractLen;
    // Presentation Context body = ctxID + 3 reserved + abstract syntax item.
    const unsigned long pcBody        = 4 + abstractItem;
    const unsigned long pcItem        = 4 + pcBody;
    const unsigned long maxLenItem    = 4 + 4;            // Max Length sub-item (body = 4-byte maxPDU)
    const unsigned long implItem      = 4 + implLen;      // Implementation Class UID sub-item
    const unsigned long userInfoBody  = maxLenItem + implItem;
    const unsigned long userInfoItem  = 4 + userInfoBody;

    // Fixed A-ASSOCIATE-RQ header before variable items:
    //   protocol(2) + reserved(2) + calledAE(16) + callingAE(16) + reserved(32) = 68
    const unsigned long fixedAfterLen = 2 + 2 + 16 + 16 + 32;
    const unsigned long variableItems = appCtxItem + pcItem + userInfoItem;

    // PDU length field counts everything AFTER the 6-byte preamble
    // (type + reserved + 4-byte length), i.e. the fixed header plus items.
    const unsigned long pduPayloadLen = fixedAfterLen + variableItems;
    const unsigned long totalLen      = 6 + pduPayloadLen;

    unsigned char *buf = new unsigned char[totalLen];
    unsigned char *p = buf;

    // PDU preamble.
    *p++ = DUL_TYPEASSOCIATERQ;  // 0x01
    *p++ = 0x00;                 // reserved
    put_u32_be(p, pduPayloadLen);

    // Fixed header.
    put_u16_be(p, DUL_PROTOCOL); // protocol version
    *p++ = 0x00; *p++ = 0x00;    // reserved
    {
        const char *calledAE  = "RECV_SCP        "; // 16 bytes, space padded
        const char *callingAE = "SEND_SCU        "; // 16 bytes, space padded
        for (int i = 0; i < 16; ++i) *p++ = OFstatic_cast(unsigned char, calledAE[i]);
        for (int i = 0; i < 16; ++i) *p++ = OFstatic_cast(unsigned char, callingAE[i]);
    }
    for (int i = 0; i < 32; ++i) *p++ = 0x00; // reserved

    // Application Context item.
    put_subitem_header(p, DUL_TYPEAPPLICATIONCONTEXT, appCtxLen);
    for (unsigned short i = 0; i < appCtxLen; ++i) *p++ = OFstatic_cast(unsigned char, appCtx[i]);

    // Presentation Context item (with abstract syntax, NO transfer syntax).
    put_subitem_header(p, DUL_TYPEPRESENTATIONCONTEXTRQ, OFstatic_cast(unsigned short, pcBody));
    *p++ = 0x01;  // presentation context ID (odd, as required)
    *p++ = 0x00;  // reserved
    *p++ = 0x00;  // reserved (result/reason, unused in RQ)
    *p++ = 0x00;  // reserved
    //   Abstract Syntax sub-item.
    put_subitem_header(p, DUL_TYPEABSTRACTSYNTAX, abstractLen);
    for (unsigned short i = 0; i < abstractLen; ++i) *p++ = OFstatic_cast(unsigned char, abstractStx[i]);
    //   (intentionally no Transfer Syntax sub-item)

    // User Information item.
    put_subitem_header(p, DUL_TYPEUSERINFO, OFstatic_cast(unsigned short, userInfoBody));
    //   Maximum Length sub-item (body = 4-byte maximum PDU length).
    put_subitem_header(p, DUL_TYPEMAXLENGTH, 4);
    put_u32_be(p, 16384);
    //   Implementation Class UID sub-item.
    put_subitem_header(p, DUL_TYPEIMPLEMENTATIONCLASSUID, implLen);
    for (unsigned short i = 0; i < implLen; ++i) *p++ = OFstatic_cast(unsigned char, implClassUID[i]);

    OFCHECK_EQUAL(OFstatic_cast(unsigned long, p - buf), totalLen);
    outLen = totalLen;
    return buf;
}


/* Regression test for two leaks on the receiver-side handling of an
 * A-ASSOCIATE-RQ whose single presentation context carries an Abstract Syntax
 * but ZERO Transfer Syntaxes:
 *
 *   1. parseAssociate() succeeds, then translatePresentationContextList()
 *      rejects the context with an illegal transfer-syntax count and
 *      AE_6_ExamineAssociateRequest() returns DUL_PCTRANSLATIONFAILURE. The
 *      already-parsed PRV_ASSOCIATEPDU (presentation context + user
 *      information lists) must be freed on that error path.
 *   2. translatePresentationContextList() itself must free the (empty)
 *      proposedTransferSyntax list it allocated for the rejected context.
 *
 * Both leaks are tracked in DCMTK issue #1217.
 *
 * A conformant DCMTK requestor cannot emit a zero-transfer-syntax context
 * (ASC_addPresentationContext rejects it), so the malicious PDU is crafted by
 * hand and sent over a raw TCP connection to an in-process DcmSCP. The leaks
 * are asserted implicitly by LeakSanitizer at process exit (build with
 * DCMTK_WITH_SANITIZERS=ON on Linux); the OFCHECKs below only assert the
 * harness behaved (socket connected, send succeeded, SCP thread joined).
 */
OFTEST(dcmnet_scp_assocRQ_zeroTransferSyntax_no_leak)
{
    OFStandard::initializeNetwork();

    OneShotReceiverSCP scp;
    // The listen socket is already bound and listening (openListenPort() runs
    // in the SCP constructor), so a client connect() succeeds via the TCP
    // backlog even before the accept thread is scheduled -- no startup sleep
    // is needed here.
    scp.start();

    DcmNativeSocketType sock = connect_loopback(scp.m_portNum);
    OFCHECK(sock != OFstatic_cast(DcmNativeSocketType, -1));

    if (sock != OFstatic_cast(DcmNativeSocketType, -1))
    {
        DcmTCPConnection conn(sock); // takes ownership of the socket

        unsigned long pduLen = 0;
        unsigned char *pdu = build_zero_ts_assoc_rq(pduLen);

        // Send the hand-built A-ASSOCIATE-RQ. This drives the SCP through
        // parseAssociate() + translatePresentationContextList() (the original leak path).
        unsigned long sent = 0;
        OFBool sendOk = OFTrue;
        while (sent < pduLen)
        {
            ssize_t n = conn.write(pdu + sent, OFstatic_cast(size_t, pduLen - sent));
            if (n <= 0) { sendOk = OFFalse; break; }
            sent += OFstatic_cast(unsigned long, n);
        }
        OFCHECK(sendOk);

        // Close immediately after sending instead of reading a response. The
        // buffered PDU is still delivered to the SCP before the FIN, so it
        // reaches the leak path; the FIN then unblocks the SCP's receive call
        // at once. Reading here would instead leave both ends blocked on each
        // other until the socket receive timeout (dcmSocketReceiveTimeout,
        // 60s by default) expired -- which made this test take ~63s.
        delete[] pdu;
        conn.close();
    }

    // Wait for the SCP thread to finish handling the (failed) association.
    const int joinResult = scp.join();
    OFCHECK(joinResult != OFThread::busy);
}

#endif // WITH_THREADS
