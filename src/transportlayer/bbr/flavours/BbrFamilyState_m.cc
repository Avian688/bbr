//
// Generated file, do not edit! Created by opp_msgtool 6.0 from transportlayer/bbr/flavours/BbrFamilyState.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#  pragma warning(disable:4101)
#  pragma warning(disable:4065)
#endif

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wshadow"
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wunused-parameter"
#  pragma clang diagnostic ignored "-Wc++98-compat"
#  pragma clang diagnostic ignored "-Wunreachable-code-break"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wshadow"
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#  pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#  pragma GCC diagnostic ignored "-Wfloat-conversion"
#endif

#include <iostream>
#include <sstream>
#include <memory>
#include <type_traits>
#include "BbrFamilyState_m.h"

namespace omnetpp {

// Template pack/unpack rules. They are declared *after* a1l type-specific pack functions for multiple reasons.
// They are in the omnetpp namespace, to allow them to be found by argument-dependent lookup via the cCommBuffer argument

// Packing/unpacking an std::vector
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::vector<T,A>& v)
{
    int n = v.size();
    doParsimPacking(buffer, n);
    for (int i = 0; i < n; i++)
        doParsimPacking(buffer, v[i]);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::vector<T,A>& v)
{
    int n;
    doParsimUnpacking(buffer, n);
    v.resize(n);
    for (int i = 0; i < n; i++)
        doParsimUnpacking(buffer, v[i]);
}

// Packing/unpacking an std::list
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::list<T,A>& l)
{
    doParsimPacking(buffer, (int)l.size());
    for (typename std::list<T,A>::const_iterator it = l.begin(); it != l.end(); ++it)
        doParsimPacking(buffer, (T&)*it);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::list<T,A>& l)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        l.push_back(T());
        doParsimUnpacking(buffer, l.back());
    }
}

// Packing/unpacking an std::set
template<typename T, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::set<T,Tr,A>& s)
{
    doParsimPacking(buffer, (int)s.size());
    for (typename std::set<T,Tr,A>::const_iterator it = s.begin(); it != s.end(); ++it)
        doParsimPacking(buffer, *it);
}

template<typename T, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::set<T,Tr,A>& s)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        T x;
        doParsimUnpacking(buffer, x);
        s.insert(x);
    }
}

// Packing/unpacking an std::map
template<typename K, typename V, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::map<K,V,Tr,A>& m)
{
    doParsimPacking(buffer, (int)m.size());
    for (typename std::map<K,V,Tr,A>::const_iterator it = m.begin(); it != m.end(); ++it) {
        doParsimPacking(buffer, it->first);
        doParsimPacking(buffer, it->second);
    }
}

template<typename K, typename V, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::map<K,V,Tr,A>& m)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        K k; V v;
        doParsimUnpacking(buffer, k);
        doParsimUnpacking(buffer, v);
        m[k] = v;
    }
}

// Default pack/unpack function for arrays
template<typename T>
void doParsimArrayPacking(omnetpp::cCommBuffer *b, const T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimPacking(b, t[i]);
}

template<typename T>
void doParsimArrayUnpacking(omnetpp::cCommBuffer *b, T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimUnpacking(b, t[i]);
}

// Default rule to prevent compiler from choosing base class' doParsimPacking() function
template<typename T>
void doParsimPacking(omnetpp::cCommBuffer *, const T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimPacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

template<typename T>
void doParsimUnpacking(omnetpp::cCommBuffer *, T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimUnpacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

}  // namespace omnetpp

namespace inet {
namespace tcp {

BbrFamilyStateVariables::BbrFamilyStateVariables()
{
}

void __doPacking(omnetpp::cCommBuffer *b, const BbrFamilyStateVariables& a)
{
    doParsimPacking(b,(::inet::tcp::TcpTahoeRenoFamilyStateVariables&)a);
    doParsimPacking(b,a.lastUpdateSeq);
    doParsimPacking(b,a.R);
    doParsimPacking(b,a.rttCount);
    doParsimPacking(b,a.firstSentTime);
    doParsimPacking(b,a.deliveredTime);
    doParsimPacking(b,a.m_delivered);
    doParsimPacking(b,a.isAppLimited);
    doParsimPacking(b,a.m_bandwidthWindowLength);
    doParsimPacking(b,a.connMinRtt);
    doParsimPacking(b,a.m_lastRtt);
    doParsimPacking(b,a.m_nextRoundDelivered);
    doParsimPacking(b,a.m_roundCount);
    doParsimPacking(b,a.m_roundStart);
    doParsimPacking(b,a.m_packetConservation);
    doParsimPacking(b,a.m_cycleStamp);
    doParsimPacking(b,a.m_cycleIndex);
    doParsimPacking(b,a.m_minRttExpired);
    doParsimPacking(b,a.m_pacingGain);
    doParsimPacking(b,a.m_cWndGain);
    doParsimPacking(b,a.m_highGain);
    doParsimPacking(b,a.m_minRtt);
    doParsimPacking(b,a.m_minRttStamp);
    doParsimPacking(b,a.m_minRttFilterLen);
    doParsimPacking(b,a.m_sendQuantum);
    doParsimPacking(b,a.m_isPipeFilled);
    doParsimPacking(b,a.m_fullBandwidth);
    doParsimPacking(b,a.m_fullBandwidthCount);
    doParsimPacking(b,a.m_idleRestart);
    doParsimPacking(b,a.m_probeRttDuration);
    doParsimPacking(b,a.m_probeRttDoneStamp);
    doParsimPacking(b,a.m_probeRttRoundDone);
    doParsimPacking(b,a.m_appLimited);
    doParsimPacking(b,a.m_minPipeCwnd);
    doParsimPacking(b,a.m_priorCwnd);
    doParsimPacking(b,a.m_hasSeenRtt);
    doParsimPacking(b,a.m_pacingMargin);
    doParsimPacking(b,a.m_initialCWnd);
    doParsimPacking(b,a.m_targetCWnd);
    doParsimPacking(b,a.m_isInitialized);
    doParsimPacking(b,a.m_extraAckedGain);
    doParsimPacking(b,a.m_extraAckedWinRtt);
    doParsimPacking(b,a.m_extraAckedWinRttLength);
    doParsimPacking(b,a.m_extraAckedIdx);
    doParsimPacking(b,a.m_ackEpochTime);
    doParsimPacking(b,a.m_ackEpochAckedResetThresh);
    doParsimPacking(b,a.m_ackEpochAcked);
    doParsimPacking(b,a.m_segmentSize);
}

void __doUnpacking(omnetpp::cCommBuffer *b, BbrFamilyStateVariables& a)
{
    doParsimUnpacking(b,(::inet::tcp::TcpTahoeRenoFamilyStateVariables&)a);
    doParsimUnpacking(b,a.lastUpdateSeq);
    doParsimUnpacking(b,a.R);
    doParsimUnpacking(b,a.rttCount);
    doParsimUnpacking(b,a.firstSentTime);
    doParsimUnpacking(b,a.deliveredTime);
    doParsimUnpacking(b,a.m_delivered);
    doParsimUnpacking(b,a.isAppLimited);
    doParsimUnpacking(b,a.m_bandwidthWindowLength);
    doParsimUnpacking(b,a.connMinRtt);
    doParsimUnpacking(b,a.m_lastRtt);
    doParsimUnpacking(b,a.m_nextRoundDelivered);
    doParsimUnpacking(b,a.m_roundCount);
    doParsimUnpacking(b,a.m_roundStart);
    doParsimUnpacking(b,a.m_packetConservation);
    doParsimUnpacking(b,a.m_cycleStamp);
    doParsimUnpacking(b,a.m_cycleIndex);
    doParsimUnpacking(b,a.m_minRttExpired);
    doParsimUnpacking(b,a.m_pacingGain);
    doParsimUnpacking(b,a.m_cWndGain);
    doParsimUnpacking(b,a.m_highGain);
    doParsimUnpacking(b,a.m_minRtt);
    doParsimUnpacking(b,a.m_minRttStamp);
    doParsimUnpacking(b,a.m_minRttFilterLen);
    doParsimUnpacking(b,a.m_sendQuantum);
    doParsimUnpacking(b,a.m_isPipeFilled);
    doParsimUnpacking(b,a.m_fullBandwidth);
    doParsimUnpacking(b,a.m_fullBandwidthCount);
    doParsimUnpacking(b,a.m_idleRestart);
    doParsimUnpacking(b,a.m_probeRttDuration);
    doParsimUnpacking(b,a.m_probeRttDoneStamp);
    doParsimUnpacking(b,a.m_probeRttRoundDone);
    doParsimUnpacking(b,a.m_appLimited);
    doParsimUnpacking(b,a.m_minPipeCwnd);
    doParsimUnpacking(b,a.m_priorCwnd);
    doParsimUnpacking(b,a.m_hasSeenRtt);
    doParsimUnpacking(b,a.m_pacingMargin);
    doParsimUnpacking(b,a.m_initialCWnd);
    doParsimUnpacking(b,a.m_targetCWnd);
    doParsimUnpacking(b,a.m_isInitialized);
    doParsimUnpacking(b,a.m_extraAckedGain);
    doParsimUnpacking(b,a.m_extraAckedWinRtt);
    doParsimUnpacking(b,a.m_extraAckedWinRttLength);
    doParsimUnpacking(b,a.m_extraAckedIdx);
    doParsimUnpacking(b,a.m_ackEpochTime);
    doParsimUnpacking(b,a.m_ackEpochAckedResetThresh);
    doParsimUnpacking(b,a.m_ackEpochAcked);
    doParsimUnpacking(b,a.m_segmentSize);
}

class BbrFamilyStateVariablesDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertyNames;
    enum FieldConstants {
        FIELD_lastUpdateSeq,
        FIELD_R,
        FIELD_rttCount,
        FIELD_firstSentTime,
        FIELD_deliveredTime,
        FIELD_m_delivered,
        FIELD_isAppLimited,
        FIELD_m_bandwidthWindowLength,
        FIELD_connMinRtt,
        FIELD_m_lastRtt,
        FIELD_m_nextRoundDelivered,
        FIELD_m_roundCount,
        FIELD_m_roundStart,
        FIELD_m_packetConservation,
        FIELD_m_cycleStamp,
        FIELD_m_cycleIndex,
        FIELD_m_minRttExpired,
        FIELD_m_pacingGain,
        FIELD_m_cWndGain,
        FIELD_m_highGain,
        FIELD_m_minRtt,
        FIELD_m_minRttStamp,
        FIELD_m_minRttFilterLen,
        FIELD_m_sendQuantum,
        FIELD_m_isPipeFilled,
        FIELD_m_fullBandwidth,
        FIELD_m_fullBandwidthCount,
        FIELD_m_idleRestart,
        FIELD_m_probeRttDuration,
        FIELD_m_probeRttDoneStamp,
        FIELD_m_probeRttRoundDone,
        FIELD_m_appLimited,
        FIELD_m_minPipeCwnd,
        FIELD_m_priorCwnd,
        FIELD_m_hasSeenRtt,
        FIELD_m_pacingMargin,
        FIELD_m_initialCWnd,
        FIELD_m_targetCWnd,
        FIELD_m_isInitialized,
        FIELD_m_extraAckedGain,
        FIELD_m_extraAckedWinRtt,
        FIELD_m_extraAckedWinRttLength,
        FIELD_m_extraAckedIdx,
        FIELD_m_ackEpochTime,
        FIELD_m_ackEpochAckedResetThresh,
        FIELD_m_ackEpochAcked,
        FIELD_m_segmentSize,
    };
  public:
    BbrFamilyStateVariablesDescriptor();
    virtual ~BbrFamilyStateVariablesDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyName) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyName) const override;
    virtual int getFieldArraySize(omnetpp::any_ptr object, int field) const override;
    virtual void setFieldArraySize(omnetpp::any_ptr object, int field, int size) const override;

    virtual const char *getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const override;
    virtual std::string getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const override;
    virtual omnetpp::cValue getFieldValue(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual omnetpp::any_ptr getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const override;
};

Register_ClassDescriptor(BbrFamilyStateVariablesDescriptor)

BbrFamilyStateVariablesDescriptor::BbrFamilyStateVariablesDescriptor() : omnetpp::cClassDescriptor(omnetpp::opp_typename(typeid(inet::tcp::BbrFamilyStateVariables)), "inet::tcp::TcpTahoeRenoFamilyStateVariables")
{
    propertyNames = nullptr;
}

BbrFamilyStateVariablesDescriptor::~BbrFamilyStateVariablesDescriptor()
{
    delete[] propertyNames;
}

bool BbrFamilyStateVariablesDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<BbrFamilyStateVariables *>(obj)!=nullptr;
}

const char **BbrFamilyStateVariablesDescriptor::getPropertyNames() const
{
    if (!propertyNames) {
        static const char *names[] = { "descriptor",  nullptr };
        omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
        const char **baseNames = base ? base->getPropertyNames() : nullptr;
        propertyNames = mergeLists(baseNames, names);
    }
    return propertyNames;
}

const char *BbrFamilyStateVariablesDescriptor::getProperty(const char *propertyName) const
{
    if (!strcmp(propertyName, "descriptor")) return "readonly";
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? base->getProperty(propertyName) : nullptr;
}

int BbrFamilyStateVariablesDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? 47+base->getFieldCount() : 47;
}

unsigned int BbrFamilyStateVariablesDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeFlags(field);
        field -= base->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        0,    // FIELD_lastUpdateSeq
        0,    // FIELD_R
        0,    // FIELD_rttCount
        0,    // FIELD_firstSentTime
        0,    // FIELD_deliveredTime
        0,    // FIELD_m_delivered
        0,    // FIELD_isAppLimited
        0,    // FIELD_m_bandwidthWindowLength
        0,    // FIELD_connMinRtt
        0,    // FIELD_m_lastRtt
        0,    // FIELD_m_nextRoundDelivered
        0,    // FIELD_m_roundCount
        0,    // FIELD_m_roundStart
        0,    // FIELD_m_packetConservation
        0,    // FIELD_m_cycleStamp
        0,    // FIELD_m_cycleIndex
        0,    // FIELD_m_minRttExpired
        0,    // FIELD_m_pacingGain
        0,    // FIELD_m_cWndGain
        0,    // FIELD_m_highGain
        0,    // FIELD_m_minRtt
        0,    // FIELD_m_minRttStamp
        0,    // FIELD_m_minRttFilterLen
        0,    // FIELD_m_sendQuantum
        0,    // FIELD_m_isPipeFilled
        0,    // FIELD_m_fullBandwidth
        0,    // FIELD_m_fullBandwidthCount
        0,    // FIELD_m_idleRestart
        0,    // FIELD_m_probeRttDuration
        0,    // FIELD_m_probeRttDoneStamp
        0,    // FIELD_m_probeRttRoundDone
        0,    // FIELD_m_appLimited
        0,    // FIELD_m_minPipeCwnd
        0,    // FIELD_m_priorCwnd
        0,    // FIELD_m_hasSeenRtt
        0,    // FIELD_m_pacingMargin
        0,    // FIELD_m_initialCWnd
        0,    // FIELD_m_targetCWnd
        0,    // FIELD_m_isInitialized
        0,    // FIELD_m_extraAckedGain
        0,    // FIELD_m_extraAckedWinRtt
        0,    // FIELD_m_extraAckedWinRttLength
        0,    // FIELD_m_extraAckedIdx
        0,    // FIELD_m_ackEpochTime
        0,    // FIELD_m_ackEpochAckedResetThresh
        0,    // FIELD_m_ackEpochAcked
        0,    // FIELD_m_segmentSize
    };
    return (field >= 0 && field < 47) ? fieldTypeFlags[field] : 0;
}

const char *BbrFamilyStateVariablesDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldName(field);
        field -= base->getFieldCount();
    }
    static const char *fieldNames[] = {
        "lastUpdateSeq",
        "R",
        "rttCount",
        "firstSentTime",
        "deliveredTime",
        "m_delivered",
        "isAppLimited",
        "m_bandwidthWindowLength",
        "connMinRtt",
        "m_lastRtt",
        "m_nextRoundDelivered",
        "m_roundCount",
        "m_roundStart",
        "m_packetConservation",
        "m_cycleStamp",
        "m_cycleIndex",
        "m_minRttExpired",
        "m_pacingGain",
        "m_cWndGain",
        "m_highGain",
        "m_minRtt",
        "m_minRttStamp",
        "m_minRttFilterLen",
        "m_sendQuantum",
        "m_isPipeFilled",
        "m_fullBandwidth",
        "m_fullBandwidthCount",
        "m_idleRestart",
        "m_probeRttDuration",
        "m_probeRttDoneStamp",
        "m_probeRttRoundDone",
        "m_appLimited",
        "m_minPipeCwnd",
        "m_priorCwnd",
        "m_hasSeenRtt",
        "m_pacingMargin",
        "m_initialCWnd",
        "m_targetCWnd",
        "m_isInitialized",
        "m_extraAckedGain",
        "m_extraAckedWinRtt",
        "m_extraAckedWinRttLength",
        "m_extraAckedIdx",
        "m_ackEpochTime",
        "m_ackEpochAckedResetThresh",
        "m_ackEpochAcked",
        "m_segmentSize",
    };
    return (field >= 0 && field < 47) ? fieldNames[field] : nullptr;
}

int BbrFamilyStateVariablesDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    int baseIndex = base ? base->getFieldCount() : 0;
    if (strcmp(fieldName, "lastUpdateSeq") == 0) return baseIndex + 0;
    if (strcmp(fieldName, "R") == 0) return baseIndex + 1;
    if (strcmp(fieldName, "rttCount") == 0) return baseIndex + 2;
    if (strcmp(fieldName, "firstSentTime") == 0) return baseIndex + 3;
    if (strcmp(fieldName, "deliveredTime") == 0) return baseIndex + 4;
    if (strcmp(fieldName, "m_delivered") == 0) return baseIndex + 5;
    if (strcmp(fieldName, "isAppLimited") == 0) return baseIndex + 6;
    if (strcmp(fieldName, "m_bandwidthWindowLength") == 0) return baseIndex + 7;
    if (strcmp(fieldName, "connMinRtt") == 0) return baseIndex + 8;
    if (strcmp(fieldName, "m_lastRtt") == 0) return baseIndex + 9;
    if (strcmp(fieldName, "m_nextRoundDelivered") == 0) return baseIndex + 10;
    if (strcmp(fieldName, "m_roundCount") == 0) return baseIndex + 11;
    if (strcmp(fieldName, "m_roundStart") == 0) return baseIndex + 12;
    if (strcmp(fieldName, "m_packetConservation") == 0) return baseIndex + 13;
    if (strcmp(fieldName, "m_cycleStamp") == 0) return baseIndex + 14;
    if (strcmp(fieldName, "m_cycleIndex") == 0) return baseIndex + 15;
    if (strcmp(fieldName, "m_minRttExpired") == 0) return baseIndex + 16;
    if (strcmp(fieldName, "m_pacingGain") == 0) return baseIndex + 17;
    if (strcmp(fieldName, "m_cWndGain") == 0) return baseIndex + 18;
    if (strcmp(fieldName, "m_highGain") == 0) return baseIndex + 19;
    if (strcmp(fieldName, "m_minRtt") == 0) return baseIndex + 20;
    if (strcmp(fieldName, "m_minRttStamp") == 0) return baseIndex + 21;
    if (strcmp(fieldName, "m_minRttFilterLen") == 0) return baseIndex + 22;
    if (strcmp(fieldName, "m_sendQuantum") == 0) return baseIndex + 23;
    if (strcmp(fieldName, "m_isPipeFilled") == 0) return baseIndex + 24;
    if (strcmp(fieldName, "m_fullBandwidth") == 0) return baseIndex + 25;
    if (strcmp(fieldName, "m_fullBandwidthCount") == 0) return baseIndex + 26;
    if (strcmp(fieldName, "m_idleRestart") == 0) return baseIndex + 27;
    if (strcmp(fieldName, "m_probeRttDuration") == 0) return baseIndex + 28;
    if (strcmp(fieldName, "m_probeRttDoneStamp") == 0) return baseIndex + 29;
    if (strcmp(fieldName, "m_probeRttRoundDone") == 0) return baseIndex + 30;
    if (strcmp(fieldName, "m_appLimited") == 0) return baseIndex + 31;
    if (strcmp(fieldName, "m_minPipeCwnd") == 0) return baseIndex + 32;
    if (strcmp(fieldName, "m_priorCwnd") == 0) return baseIndex + 33;
    if (strcmp(fieldName, "m_hasSeenRtt") == 0) return baseIndex + 34;
    if (strcmp(fieldName, "m_pacingMargin") == 0) return baseIndex + 35;
    if (strcmp(fieldName, "m_initialCWnd") == 0) return baseIndex + 36;
    if (strcmp(fieldName, "m_targetCWnd") == 0) return baseIndex + 37;
    if (strcmp(fieldName, "m_isInitialized") == 0) return baseIndex + 38;
    if (strcmp(fieldName, "m_extraAckedGain") == 0) return baseIndex + 39;
    if (strcmp(fieldName, "m_extraAckedWinRtt") == 0) return baseIndex + 40;
    if (strcmp(fieldName, "m_extraAckedWinRttLength") == 0) return baseIndex + 41;
    if (strcmp(fieldName, "m_extraAckedIdx") == 0) return baseIndex + 42;
    if (strcmp(fieldName, "m_ackEpochTime") == 0) return baseIndex + 43;
    if (strcmp(fieldName, "m_ackEpochAckedResetThresh") == 0) return baseIndex + 44;
    if (strcmp(fieldName, "m_ackEpochAcked") == 0) return baseIndex + 45;
    if (strcmp(fieldName, "m_segmentSize") == 0) return baseIndex + 46;
    return base ? base->findField(fieldName) : -1;
}

const char *BbrFamilyStateVariablesDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeString(field);
        field -= base->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "uint32_t",    // FIELD_lastUpdateSeq
        "double",    // FIELD_R
        "int",    // FIELD_rttCount
        "double",    // FIELD_firstSentTime
        "double",    // FIELD_deliveredTime
        "long",    // FIELD_m_delivered
        "bool",    // FIELD_isAppLimited
        "uint32_t",    // FIELD_m_bandwidthWindowLength
        "omnetpp::simtime_t",    // FIELD_connMinRtt
        "omnetpp::simtime_t",    // FIELD_m_lastRtt
        "uint32",    // FIELD_m_nextRoundDelivered
        "uint32",    // FIELD_m_roundCount
        "bool",    // FIELD_m_roundStart
        "bool",    // FIELD_m_packetConservation
        "omnetpp::simtime_t",    // FIELD_m_cycleStamp
        "uint32_t",    // FIELD_m_cycleIndex
        "bool",    // FIELD_m_minRttExpired
        "double",    // FIELD_m_pacingGain
        "double",    // FIELD_m_cWndGain
        "double",    // FIELD_m_highGain
        "omnetpp::simtime_t",    // FIELD_m_minRtt
        "omnetpp::simtime_t",    // FIELD_m_minRttStamp
        "omnetpp::simtime_t",    // FIELD_m_minRttFilterLen
        "uint32_t",    // FIELD_m_sendQuantum
        "bool",    // FIELD_m_isPipeFilled
        "uint32_t",    // FIELD_m_fullBandwidth
        "uint32_t",    // FIELD_m_fullBandwidthCount
        "bool",    // FIELD_m_idleRestart
        "omnetpp::simtime_t",    // FIELD_m_probeRttDuration
        "omnetpp::simtime_t",    // FIELD_m_probeRttDoneStamp
        "bool",    // FIELD_m_probeRttRoundDone
        "bool",    // FIELD_m_appLimited
        "uint32_t",    // FIELD_m_minPipeCwnd
        "uint32_t",    // FIELD_m_priorCwnd
        "bool",    // FIELD_m_hasSeenRtt
        "double",    // FIELD_m_pacingMargin
        "uint32_t",    // FIELD_m_initialCWnd
        "uint32_t",    // FIELD_m_targetCWnd
        "bool",    // FIELD_m_isInitialized
        "uint32_t",    // FIELD_m_extraAckedGain
        "uint32_t",    // FIELD_m_extraAckedWinRtt
        "uint32_t",    // FIELD_m_extraAckedWinRttLength
        "uint32_t",    // FIELD_m_extraAckedIdx
        "omnetpp::simtime_t",    // FIELD_m_ackEpochTime
        "uint32_t",    // FIELD_m_ackEpochAckedResetThresh
        "uint32_t",    // FIELD_m_ackEpochAcked
        "uint32_t",    // FIELD_m_segmentSize
    };
    return (field >= 0 && field < 47) ? fieldTypeStrings[field] : nullptr;
}

const char **BbrFamilyStateVariablesDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldPropertyNames(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *BbrFamilyStateVariablesDescriptor::getFieldProperty(int field, const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldProperty(field, propertyName);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int BbrFamilyStateVariablesDescriptor::getFieldArraySize(omnetpp::any_ptr object, int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldArraySize(object, field);
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        default: return 0;
    }
}

void BbrFamilyStateVariablesDescriptor::setFieldArraySize(omnetpp::any_ptr object, int field, int size) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldArraySize(object, field, size);
            return;
        }
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set array size of field %d of class 'BbrFamilyStateVariables'", field);
    }
}

const char *BbrFamilyStateVariablesDescriptor::getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldDynamicTypeString(object,field,i);
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string BbrFamilyStateVariablesDescriptor::getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValueAsString(object,field,i);
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        case FIELD_lastUpdateSeq: return ulong2string(pp->lastUpdateSeq);
        case FIELD_R: return double2string(pp->R);
        case FIELD_rttCount: return long2string(pp->rttCount);
        case FIELD_firstSentTime: return double2string(pp->firstSentTime);
        case FIELD_deliveredTime: return double2string(pp->deliveredTime);
        case FIELD_m_delivered: return long2string(pp->m_delivered);
        case FIELD_isAppLimited: return bool2string(pp->isAppLimited);
        case FIELD_m_bandwidthWindowLength: return ulong2string(pp->m_bandwidthWindowLength);
        case FIELD_connMinRtt: return simtime2string(pp->connMinRtt);
        case FIELD_m_lastRtt: return simtime2string(pp->m_lastRtt);
        case FIELD_m_nextRoundDelivered: return ulong2string(pp->m_nextRoundDelivered);
        case FIELD_m_roundCount: return ulong2string(pp->m_roundCount);
        case FIELD_m_roundStart: return bool2string(pp->m_roundStart);
        case FIELD_m_packetConservation: return bool2string(pp->m_packetConservation);
        case FIELD_m_cycleStamp: return simtime2string(pp->m_cycleStamp);
        case FIELD_m_cycleIndex: return ulong2string(pp->m_cycleIndex);
        case FIELD_m_minRttExpired: return bool2string(pp->m_minRttExpired);
        case FIELD_m_pacingGain: return double2string(pp->m_pacingGain);
        case FIELD_m_cWndGain: return double2string(pp->m_cWndGain);
        case FIELD_m_highGain: return double2string(pp->m_highGain);
        case FIELD_m_minRtt: return simtime2string(pp->m_minRtt);
        case FIELD_m_minRttStamp: return simtime2string(pp->m_minRttStamp);
        case FIELD_m_minRttFilterLen: return simtime2string(pp->m_minRttFilterLen);
        case FIELD_m_sendQuantum: return ulong2string(pp->m_sendQuantum);
        case FIELD_m_isPipeFilled: return bool2string(pp->m_isPipeFilled);
        case FIELD_m_fullBandwidth: return ulong2string(pp->m_fullBandwidth);
        case FIELD_m_fullBandwidthCount: return ulong2string(pp->m_fullBandwidthCount);
        case FIELD_m_idleRestart: return bool2string(pp->m_idleRestart);
        case FIELD_m_probeRttDuration: return simtime2string(pp->m_probeRttDuration);
        case FIELD_m_probeRttDoneStamp: return simtime2string(pp->m_probeRttDoneStamp);
        case FIELD_m_probeRttRoundDone: return bool2string(pp->m_probeRttRoundDone);
        case FIELD_m_appLimited: return bool2string(pp->m_appLimited);
        case FIELD_m_minPipeCwnd: return ulong2string(pp->m_minPipeCwnd);
        case FIELD_m_priorCwnd: return ulong2string(pp->m_priorCwnd);
        case FIELD_m_hasSeenRtt: return bool2string(pp->m_hasSeenRtt);
        case FIELD_m_pacingMargin: return double2string(pp->m_pacingMargin);
        case FIELD_m_initialCWnd: return ulong2string(pp->m_initialCWnd);
        case FIELD_m_targetCWnd: return ulong2string(pp->m_targetCWnd);
        case FIELD_m_isInitialized: return bool2string(pp->m_isInitialized);
        case FIELD_m_extraAckedGain: return ulong2string(pp->m_extraAckedGain);
        case FIELD_m_extraAckedWinRtt: return ulong2string(pp->m_extraAckedWinRtt);
        case FIELD_m_extraAckedWinRttLength: return ulong2string(pp->m_extraAckedWinRttLength);
        case FIELD_m_extraAckedIdx: return ulong2string(pp->m_extraAckedIdx);
        case FIELD_m_ackEpochTime: return simtime2string(pp->m_ackEpochTime);
        case FIELD_m_ackEpochAckedResetThresh: return ulong2string(pp->m_ackEpochAckedResetThresh);
        case FIELD_m_ackEpochAcked: return ulong2string(pp->m_ackEpochAcked);
        case FIELD_m_segmentSize: return ulong2string(pp->m_segmentSize);
        default: return "";
    }
}

void BbrFamilyStateVariablesDescriptor::setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValueAsString(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'BbrFamilyStateVariables'", field);
    }
}

omnetpp::cValue BbrFamilyStateVariablesDescriptor::getFieldValue(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValue(object,field,i);
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        case FIELD_lastUpdateSeq: return (omnetpp::intval_t)(pp->lastUpdateSeq);
        case FIELD_R: return pp->R;
        case FIELD_rttCount: return pp->rttCount;
        case FIELD_firstSentTime: return pp->firstSentTime;
        case FIELD_deliveredTime: return pp->deliveredTime;
        case FIELD_m_delivered: return (omnetpp::intval_t)(pp->m_delivered);
        case FIELD_isAppLimited: return pp->isAppLimited;
        case FIELD_m_bandwidthWindowLength: return (omnetpp::intval_t)(pp->m_bandwidthWindowLength);
        case FIELD_connMinRtt: return pp->connMinRtt.dbl();
        case FIELD_m_lastRtt: return pp->m_lastRtt.dbl();
        case FIELD_m_nextRoundDelivered: return (omnetpp::intval_t)(pp->m_nextRoundDelivered);
        case FIELD_m_roundCount: return (omnetpp::intval_t)(pp->m_roundCount);
        case FIELD_m_roundStart: return pp->m_roundStart;
        case FIELD_m_packetConservation: return pp->m_packetConservation;
        case FIELD_m_cycleStamp: return pp->m_cycleStamp.dbl();
        case FIELD_m_cycleIndex: return (omnetpp::intval_t)(pp->m_cycleIndex);
        case FIELD_m_minRttExpired: return pp->m_minRttExpired;
        case FIELD_m_pacingGain: return pp->m_pacingGain;
        case FIELD_m_cWndGain: return pp->m_cWndGain;
        case FIELD_m_highGain: return pp->m_highGain;
        case FIELD_m_minRtt: return pp->m_minRtt.dbl();
        case FIELD_m_minRttStamp: return pp->m_minRttStamp.dbl();
        case FIELD_m_minRttFilterLen: return pp->m_minRttFilterLen.dbl();
        case FIELD_m_sendQuantum: return (omnetpp::intval_t)(pp->m_sendQuantum);
        case FIELD_m_isPipeFilled: return pp->m_isPipeFilled;
        case FIELD_m_fullBandwidth: return (omnetpp::intval_t)(pp->m_fullBandwidth);
        case FIELD_m_fullBandwidthCount: return (omnetpp::intval_t)(pp->m_fullBandwidthCount);
        case FIELD_m_idleRestart: return pp->m_idleRestart;
        case FIELD_m_probeRttDuration: return pp->m_probeRttDuration.dbl();
        case FIELD_m_probeRttDoneStamp: return pp->m_probeRttDoneStamp.dbl();
        case FIELD_m_probeRttRoundDone: return pp->m_probeRttRoundDone;
        case FIELD_m_appLimited: return pp->m_appLimited;
        case FIELD_m_minPipeCwnd: return (omnetpp::intval_t)(pp->m_minPipeCwnd);
        case FIELD_m_priorCwnd: return (omnetpp::intval_t)(pp->m_priorCwnd);
        case FIELD_m_hasSeenRtt: return pp->m_hasSeenRtt;
        case FIELD_m_pacingMargin: return pp->m_pacingMargin;
        case FIELD_m_initialCWnd: return (omnetpp::intval_t)(pp->m_initialCWnd);
        case FIELD_m_targetCWnd: return (omnetpp::intval_t)(pp->m_targetCWnd);
        case FIELD_m_isInitialized: return pp->m_isInitialized;
        case FIELD_m_extraAckedGain: return (omnetpp::intval_t)(pp->m_extraAckedGain);
        case FIELD_m_extraAckedWinRtt: return (omnetpp::intval_t)(pp->m_extraAckedWinRtt);
        case FIELD_m_extraAckedWinRttLength: return (omnetpp::intval_t)(pp->m_extraAckedWinRttLength);
        case FIELD_m_extraAckedIdx: return (omnetpp::intval_t)(pp->m_extraAckedIdx);
        case FIELD_m_ackEpochTime: return pp->m_ackEpochTime.dbl();
        case FIELD_m_ackEpochAckedResetThresh: return (omnetpp::intval_t)(pp->m_ackEpochAckedResetThresh);
        case FIELD_m_ackEpochAcked: return (omnetpp::intval_t)(pp->m_ackEpochAcked);
        case FIELD_m_segmentSize: return (omnetpp::intval_t)(pp->m_segmentSize);
        default: throw omnetpp::cRuntimeError("Cannot return field %d of class 'BbrFamilyStateVariables' as cValue -- field index out of range?", field);
    }
}

void BbrFamilyStateVariablesDescriptor::setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValue(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'BbrFamilyStateVariables'", field);
    }
}

const char *BbrFamilyStateVariablesDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructName(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    };
}

omnetpp::any_ptr BbrFamilyStateVariablesDescriptor::getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructValuePointer(object, field, i);
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        default: return omnetpp::any_ptr(nullptr);
    }
}

void BbrFamilyStateVariablesDescriptor::setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldStructValuePointer(object, field, i, ptr);
            return;
        }
        field -= base->getFieldCount();
    }
    BbrFamilyStateVariables *pp = omnetpp::fromAnyPtr<BbrFamilyStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'BbrFamilyStateVariables'", field);
    }
}

}  // namespace tcp
}  // namespace inet

namespace omnetpp {

template<> inet::tcp::BbrFamilyStateVariables *fromAnyPtr(any_ptr ptr) {
    if (ptr.contains<inet::tcp::TcpStateVariables>()) return static_cast<inet::tcp::BbrFamilyStateVariables*>(ptr.get<inet::tcp::TcpStateVariables>());
    if (ptr.contains<omnetpp::cObject>()) return static_cast<inet::tcp::BbrFamilyStateVariables*>(ptr.get<omnetpp::cObject>());
    throw cRuntimeError("Unable to obtain inet::tcp::BbrFamilyStateVariables* pointer from any_ptr(%s)", ptr.pointerTypeName());
}
}  // namespace omnetpp

