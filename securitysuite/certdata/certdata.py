# -*- encoding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Utility module for NSS certdata handling
"""

# TODO: switch generic Exception()s to dedicated module exceptions

import re
import binascii

#######################################################################################################################
# Tokenizer for certdata.txt files
##################################

class CertdataToken:
    """
    Base class for tokens used in certdata parsing.
    Every token has an optional object .v which holds the
    content that the token refers to.
    """
    def __init__(self, value=None):
        """
        Token constructor
        :param value: an optional token value
        """
        self.v = value


class BegindataToken(CertdataToken):
    """
    Class to represent a BEGINDATA token in certdata parsing.
    It usually doesn't take a value to avoid redundancy.
    """
    pass


class AttributeToken(CertdataToken):
    """
    Class to represent an attribute name token in certdata parsing
    """
    pass


class TypeToken(CertdataToken):
    """
    Class to represent an attribute type token in certdata parsing
    """
    pass


class ValueToken(CertdataToken):
    """
    Class to represent an attribute value token in certdata parsing

    """
    pass


class MultilineEndToken(CertdataToken):
    """
    Class to represent a MULTILINE value END token in certdata parsing
    It usually doesn't take a value to avoid redundancy.
    """
    pass


def tokenize(certdata):
    """
    Tokenizer for NSS certdata.txt parsing
    :param certdata: string content of a certdata.txt file
    :return: yields token objects
    """

    # Regular expressions matching certdata.txt structures
    # It's deliberately relaxed on leading and trailing whitespace.

    # Empty lines are all over the document
    is_emptyline = re.compile(r'^\s*$')

    # Comment lines are prefaced by the '#'-character
    is_comment = re.compile(r'^\s*#')

    # The BEGINDATA keyword appears once on top of the document
    is_begindata = re.compile(r'^\s*(BEGINDATA)\s*$')

    # I have seen attribute lines in two flavors, regular and multi-line
    # Regular example:
    # r'CKA_LABEL UTF8 "Mozilla Builtin Roots"'
    # Multi-line example:
    # r'CKA_SUBJECT MULTILINE_OCTAL'
    attribute_line = re.compile(r'^(\w+)\s+(\w+)\s*(.*)$')

    # MULTILINE example:
    # r'\060\116\061\013\060\011\006\003\125\004\006\023\002\125\123\061'
    multiline_octal_value = re.compile(r'\\\d{3}')
    multiline_octal_values = re.compile(r'^\s*(\\\d{3})+$')

    # MULTILINE definitions continue until the END keyword shows up
    is_multiline_end = re.compile(r'^\s*(END)\s*$')


    # certdata.txt is a simple line-based format
    for line in certdata.split('\n'):

        # Skip comment lines
        if is_comment.match(line):
            continue

        # Skip empty lines
        if is_emptyline.match(line):
            continue

        # Test match for regular attribute lines
        m = attribute_line.match(line)
        if m:
            attribute, attrtype, value = m.groups()
            yield AttributeToken(attribute)
            yield TypeToken(attrtype)
            if attrtype == 'MULTILINE_OCTAL':
                if value:
                    raise Exception('certdata tokenizer error: unexpected value after MULTILINE_OCTAL')
                else:
                    continue
            else:
                if not value:
                    raise Exception('certdata tokenizer error: missing value')
                else:
                    yield ValueToken(value)
                    continue

        # Test match for lines containing MULTILINE values
        m = multiline_octal_values.match(line)
        if m:
            # Extract individual values
            for v in multiline_octal_value.findall(line):
                yield ValueToken(v)
            continue

        # MULTILINE values are trailed by the keyword "END"
        if is_multiline_end.match(line):
            yield MultilineEndToken()
            continue

        # The BEGINDATA keyword should only appear once and as the very first token
        if is_begindata.match(line):
            yield BegindataToken()
            continue

        raise Exception('certdata tokenizer error: invalid line format')


#######################################################################################################################
# Attributizer for certdata.txt files
#####################################

class AttributeObject:
    """
    Class containing certdata-style attributes, each consisting of a
    <name> <type> <value> triplet
    """

    def __init__(self, name, valuetype=None, value=None):
        """
        Constructor for certdata attribute objects. The optional type and
        value arguments serve as syntactic sugar.
        :param name: mandatory attribute name
        :param valuetype: optional value type passed to .set_from_stringvalues()
        :param value: optional value, mandatory if type is given
        """
        self.name = name
        if valuetype is not None and value is not None:
            self.set_from_stringvalue(valuetype, value)

    def set_from_stringvalue(self, valuetype, value):
        """
        Setter method for certdata attribute objects.
        :param valuetype: type of value, passed to parse_value() module function
        :param value: value string passed to parse_value() module function
        """
        self.type = valuetype
        self.value = parse_value(valuetype, value)


def parse_value(valuetype, value):
    """
    Parses an attribute value string representation according to its type.
    The return value's type depends on the valuetype parameter:
    MULTILINE_OCTAL: bytearray()
    CK_BOOL: True or False
    UTF8: unicode()
    else: str()

    :param valuetype: a string denoting the value type
    :param value: a string or list of strings denoting the value
    :return: a parsed value object
    """

    # normalize value parameter
    if isinstance(value, str):
        value = [value]

    if valuetype == 'MULTILINE_OCTAL':
        bytes = bytearray()
        for v in value:
            if not v.startswith('\\'):
                raise Exception('certdata parser error: invalid value format in MULTILINE_OCTAL')
            bytes.append(int(v[1:], 8))
        return bytes
    elif valuetype == 'CK_BBOOL':
        if value[0] == 'CK_FALSE':
            return False
        if value[0] == 'CK_TRUE':
            return True
        raise Exception('certdata parser error: illegal CK_BOOL value: %s' % value[0])
    elif valuetype == 'CK_CERTIFICATE_TYPE':
        return value[0]
    elif valuetype == 'CK_OBJECT_CLASS':
        return value[0]
    elif valuetype == 'CK_TRUST':
        return value[0]
    elif valuetype == 'UTF8':
        v = value[0]
        if not v.startswith('"') or not v.endswith('"'):
            raise Exception('certdata parser error: illegal UTF8 string value')
        return v[1:-1].decode('utf-8')
    else:
        raise Exception('certdata parser error: illegal type: %s' % valuetype)


def attributize(token_list):
    """
    Convert tokenizer output to triples of <attribute> <type> <values>

    :param token_list: a token list as generated by certdata.tokenizer()
    :return: yields AttributeObjects containing (name, type, value)
    """
    try:
        p = 0
        # Skip leading BEGINDATA token if present
        if isinstance(token_list[p], BegindataToken):
            p += 1
        while p < len(token_list):
            if not isinstance(token_list[p], AttributeToken):
                raise Exception('certdata parser error: first element of triplet must be an attribute')
            attribute_name = token_list[p].v
            p += 1
            if not isinstance(token_list[p], TypeToken):
                raise Exception('certdata parser error: second element of triplet must be a type declaration')
            attribute_type = token_list[p].v
            p += 1
            values = []
            while p < len(token_list) and isinstance(token_list[p], ValueToken):
                values.append(token_list[p].v)
                p += 1
            if len(values) < 1:
                raise Exception('certdata parser error: triplet missing value')
            if len(values) > 1:
                if not isinstance(token_list[p], MultilineEndToken):
                    raise Exception('certdata parser error: MULTILINE value is missing END token')
                p += 1
            yield AttributeObject(attribute_name, attribute_type, values)

    except IndexError:
        raise Exception('certdata parser error: invalid triplet syntax')


#######################################################################################################################
# Parser for certdata.txt files
#####################################

class CertdataObject:
    """
    Base class for certdata objects. Each object can hold an arbitrary
    number of named attributes.
    """
    def __init__(self):
        """
        Constructor creating an empty object
        """
        self.attributes = {}

    def __getitem__(self, key):
        """
        Getter for named attributes
        :param key: attribute name string
        :return: attribute value or None if attribute not set
        """
        try:
            return self.attributes[key]
        except KeyError:
            return None

    def __iter__(self):
        """
        Object iterator that iterates all attributes
        :return: yields certdata.AttributeObject objects
        """
        for name in self.attributes:
            yield self.attributes[name]

    def set_attribute(self, attributeobj):
        """
        Attribute setter. CAVE: It does not check for name collisions.
        :param attributeobj: an AttributeObject
        """
        self.attributes[attributeobj.name] = attributeobj

    def label(self):
        """
        Getter for object label as represented by the CKA_LABEL attribute
        :return: object label string or emptystring if no CKA_LABEL was set
        """
        try:
            return self['CKA_LABEL'].value
        except AttributeError:
            return ''

    def sha1(self):
        """
        Getter for object SHA1 as represented by the CKA_CERT_SHA1_HASH attribute
        :return: SHA1 string or emptystring if no SHA1 was set
        """
        try:
            return binascii.hexlify(self['CKA_CERT_SHA1_HASH'].value)
        except AttributeError or TypeError:
            return ''

    def md5(self):
        """
        Getter for object MD5 as represented by the CKA_CERT_MD5_HASH attribute
        :return: MD5 string or emptystring if no MD5 was set
        """
        try:
            return binascii.hexlify(self['CKA_CERT_MD5_HASH'].value)
        except AttributeError or TypeError:
            return ''

    def serial(self):
        """
        Getter for object serial as represented by the CKA_SERIAL_NUMBER attribute
        :return: serial string or emptystring if no serial was set
        """
        try:
            return binascii.hexlify(self['CKA_SERIAL_NUMBER'].value)
        except AttributeError or TypeError:
            return ''

    def id(self):
        """
        Getter for a unique object ID used for indexing
        :return: an object ID string
        """
        label = self.label()
        serial = binascii.hexlify(self.serial())
        sha = binascii.hexlify(self.sha1())
        return "%s_%s_%s" % (label, serial, sha)


class TrustObject(CertdataObject):
    """
    Class to represent an NSS Trust object
    """
    pass


class CertObject(CertdataObject):
    """
    Class to represent an NSS Certificate object
    """
    pass


class RootObject(CertdataObject):
    """
    Class to represent the "Mozilla Builtin Roots" object in NSS Certdata
    """
    pass


class CertdataCollection:
    """
    Class to represent a complete NSS Certdata Builtins object structure
    """

    def __init__(self, root=None):
        """
        Constructor of CertdataCollection objects
        :param root: an optional RootObject instance
        """
        self.root = root
        self.certs = []
        self.certindex = {}
        self.trusts = []
        self.trustindex = {}

    def add_cert(self, certobj):
        """
        Add a certificate to the certificate list
        :param certobj: a certdata.CertObject
        """
        self.certs.append(certobj)
        id = certobj.id()
        if id in self.certindex:
            raise Exception('certdata parser error: redefinition of certificate with ID %s' % id)
        self.certindex[id] = certobj

    def add_trust(self, trustobj):
        """
        Add a trust descriptor to the trust descriptor list
        :param trustobj: a certdata.TrustObject
        """
        self.trusts.append(trustobj)
        id = trustobj.id()
        if id in self.trustindex:
            raise Exception('certdata parser error: redefinition of trust entry with ID %s' % id)
        self.trustindex[id] = trustobj


def parse(certdata):
    """
    A NSS Certdata parser that turns the content of a certdata.txt file
    into a Python data structure.

    :param certdata: certdata.txt string content
    :return: a certdata.CertdataCollection
    """

    # CAVE: Significant convenience memory-hogging in progress.
    # Consider switching .attributize() to use the .tokenize() generator.
    tokens = [x for x in tokenize(certdata)]

    # some crude tests to see if we're looking at a real certdata.txt file
    if not isinstance(tokens[0], BegindataToken):
        raise Exception('certdata parser error: missing BEGINDATA token')

    # everything that follows BEGINDATA should have the following form:
    # <attribute> <type> <values>
    attributes = [x for x in attributize(tokens)]

    if attributes[0].name != 'CKA_CLASS' or attributes[0].type != 'CK_OBJECT_CLASS' or attributes[
        0].value != 'CKO_NSS_BUILTIN_ROOT_LIST':
        raise Exception('certdata parser error: missing leading CKO_NSS_BUILTIN_ROOT_LIST object')

    # parse root object header
    root_obj = RootObject()
    p = 1
    while attributes[p].name != 'CKA_CLASS':
        root_obj.set_attribute(attributes[p])
        p += 1

    certificate_data_obj = CertdataCollection(root_obj)

    new_cert_obj = None
    new_trust_obj = None
    for attribute in attributes[p:]:
        if attribute.name == 'CKA_CLASS':
            if new_cert_obj is not None:
                certificate_data_obj.add_cert(new_cert_obj)
                new_cert_obj = None
            if new_trust_obj is not None:
                certificate_data_obj.add_trust(new_trust_obj)
                new_trust_obj = None
            if attribute.value == 'CKO_CERTIFICATE':
                new_cert_obj = CertObject()
            elif attribute.value == 'CKO_NSS_TRUST':
                new_trust_obj = TrustObject()
            elif attribute.value == 'CKO_NSS_BUILTIN_ROOT_LIST':
                raise Exception('certdata parser error: unexpected CKO_NSS_BUILTIN_ROOT_LIST object')
            else:
                raise Exception('certdata parser error: unexpected CKA_CLASS value: %s' % attribute.value)

        else:
            if new_cert_obj is not None:
                new_cert_obj.set_attribute(attribute)
            elif new_trust_obj is not None:
                new_trust_obj.set_attribute(attribute)
            else:
                raise Exception('certdata parser error: internal invalid state: '
                                'creating cert and trust object simultaneously')

        # print attribute.name, attribute.type, repr(attribute.value)

    if new_cert_obj is not None:
        certificate_data_obj.add_cert(new_cert_obj)
    if new_trust_obj is not None:
        certificate_data_obj.add_trust(new_trust_obj)

    return certificate_data_obj


def parse_files(filenames):
    """
    Convenience function for parsing multiple files, typically
    a global certdata.txt and a b2g-specific b2g-certdata.txt.
    Multiple files will just be concatenated internally.

    CAVE: The main certdata.txt which starts with the BEGINDATA
    keyword and contains the "Builtin Roots" header must come first.

    :param filenames: a filename string or list of filename strings
    :return: certdata.CertdataCollection object
    """

    # Normalize filenames parameter
    if not isinstance(filenames, list):
        filenames = [filenames]
    data = ''
    for filename in filenames:
        with open(filename, 'r') as f:
            data += f.read()
    return parse(data)

if __name__ == '__main__':
    p = parse_files(['certdata.txt', 'b2g-certdata.txt'])

    print "# ROOT HEADER ###############################################################"
    for attribute in p.root:
        print attribute.name, attribute.type, repr(attribute.value)
    print "\n# CERTIFICATE OBJECTS #######################################################"
    for cert in p.certs:
        for attribute in cert:
            print attribute.name, attribute.type, repr(attribute.value)
        print
    print "\n# TRUST OBJECTS #############################################################"
    for trust in p.trusts:
        for attribute in trust:
            print attribute.name, attribute.type, repr(attribute.value)
        print

    print "\n\nTry p? for starters. <<<<<<<<<<<<<<<<<<\n\n"

    from IPython import embed
    embed()
