/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

namespace virtrust {

using xmlChar = unsigned char;

// ---------------------------------------------------------------------------
// Type definition from libxml2/libxml/tree.h
// ---------------------------------------------------------------------------

/*
 * The different element types carried by an XML tree.
 *
 * NOTE: This is synchronized with DOM Level1 values
 *       See http://www.w3.org/TR/REC-DOM-Level-1/
 *
 * Actually this had diverged a bit, and now XML_DOCUMENT_TYPE_NODE should
 * be deprecated to use an XML_DTD_NODE.
 */
typedef enum {
  XML_ELEMENT_NODE = 1,
  XML_ATTRIBUTE_NODE = 2,
  XML_TEXT_NODE = 3,
  XML_CDATA_SECTION_NODE = 4,
  XML_ENTITY_REF_NODE = 5,
  XML_ENTITY_NODE = 6,
  XML_PI_NODE = 7,
  XML_COMMENT_NODE = 8,
  XML_DOCUMENT_NODE = 9,
  XML_DOCUMENT_TYPE_NODE = 10,
  XML_DOCUMENT_FRAG_NODE = 11,
  XML_NOTATION_NODE = 12,
  XML_HTML_DOCUMENT_NODE = 13,
  XML_DTD_NODE = 14,
  XML_ELEMENT_DECL = 15,
  XML_ATTRIBUTE_DECL = 16,
  XML_ENTITY_DECL = 17,
  XML_NAMESPACE_DECL = 18,
  XML_XINCLUDE_START = 19,
  XML_XINCLUDE_END = 20
  /* XML_DOCB_DOCUMENT_NODE=	21 */ /* removed */
} xmlElementType;

/**
 * xmlNs:
 *
 * An XML namespace.
 * Note that prefix == NULL is valid, it defines the default namespace
 * within the subtree (until overridden).
 *
 * xmlNsType is unified with xmlElementType.
 */
using xmlNs = struct _xmlNs;
using xmlNsType = xmlElementType;

struct _xmlNs {
  struct _xmlNs *next;     /* next Ns link for this node  */
  xmlNsType type;          /* global or local */
  const xmlChar *href;     /* URL for the namespace */
  const xmlChar *prefix;   /* prefix for the namespace */
  void *_private;          /* application data */
  struct _xmlDoc *context; /* normally an xmlDoc */
};

/**
 * xmlDoc:
 *
 * An XML document.
 */
using xmlDoc = struct _xmlDoc;
using xmlDocPtr = xmlDoc *;

struct _xmlDoc {
  void *_private;            /* application data */
  xmlElementType type;       /* XML_DOCUMENT_NODE, must be second ! */
  char *name;                /* name/filename/URI of the document */
  struct _xmlNode *children; /* the document tree */
  struct _xmlNode *last;     /* last child link */
  struct _xmlNode *parent;   /* child->parent link */
  struct _xmlNode *next;     /* next sibling link  */
  struct _xmlNode *prev;     /* previous sibling link  */
  struct _xmlDoc *doc;       /* autoreference to itself */

  /* End of common part */
  int compression;           /* level of zlib compression */
  int standalone;            /* standalone document (no external refs)
                  1 if standalone="yes"
                  0 if standalone="no"
                 -1 if there is no XML declaration
                 -2 if there is an XML declaration, but no
                 standalone attribute was specified */
  struct _xmlDtd *intSubset; /* the document internal subset */
  struct _xmlDtd *extSubset; /* the document external subset */
  struct _xmlNs *oldNs;      /* Global namespace, the old way */
  const xmlChar *version;    /* the XML version string */
  const xmlChar *encoding;   /* external initial encoding, if any */
  void *ids;                 /* Hash table for ID attributes if any */
  void *refs;                /* Hash table for IDREFs attributes if any */
  const xmlChar *URL;        /* The URI for that document */
  int charset;               /* Internal flag for charset handling,
                actually an xmlCharEncoding */
  struct _xmlDict *dict;     /* dict used to allocate names or NULL */
  void *psvi;                /* for type/PSVI information */
  int parseFlags;            /* set of xmlParserOption used to parse the
                document */
  int properties;            /* set of xmlDocProperties for this document
                set at the end of parsing */
};

/**
 * xmlNode:
 *
 * A node in an XML tree.
 */
using xmlNode = struct _xmlNode;
using xmlNodePtr = xmlNode *;

struct _xmlNode {
  void *_private;            /* application data */
  xmlElementType type;       /* type number, must be second ! */
  const xmlChar *name;       /* the name of the node, or the entity */
  struct _xmlNode *children; /* parent->childs link */
  struct _xmlNode *last;     /* last child link */
  struct _xmlNode *parent;   /* child->parent link */
  struct _xmlNode *next;     /* next sibling link  */
  struct _xmlNode *prev;     /* previous sibling link  */
  struct _xmlDoc *doc;       /* the containing document */

  /* End of common part */
  xmlNs *ns;                   /* pointer to the associated namespace */
  xmlChar *content;            /* the content */
  struct _xmlAttr *properties; /* properties list */
  xmlNs *nsDef;                /* namespace definitions on this node */
  void *psvi;                  /* for type/PSVI information */
  unsigned short line;         /* line number */
  unsigned short extra;        /* extra data for XPath/XSLT */
};

} // namespace virtrust
