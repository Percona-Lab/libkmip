#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_protocol.hpp"

namespace kmipcore {

  // === Attribute ===

  Attribute::Attribute(const std::string &name, const std::string &value)
    : name_(name), value_(value) {}

  std::shared_ptr<Element> Attribute::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);

    structure->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, name_)
    );
    // Assuming simple TextString value for now. Real world is complex.
    structure->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_VALUE, value_)
    );

    return structure;
  }

  Attribute Attribute::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != tag::KMIP_TAG_ATTRIBUTE) {
      throw KmipException("Invalid Attribute element");
    }

    Attribute attr;
    auto name = element->getChild(tag::KMIP_TAG_ATTRIBUTE_NAME);
    if (name) {
      attr.name_ = name->toString();
    }

    auto val = element->getChild(tag::KMIP_TAG_ATTRIBUTE_VALUE);
    if (val) {
      attr.value_ = val->toString();
    }

    return attr;
  }

  // === LocateRequestPayload ===

  std::shared_ptr<Element> LocateRequestPayload::toElement() const {
    auto structure = Element::createStructure(
        tag::KMIP_TAG_REQUEST_PAYLOAD
    );  // or payload tag depending on usage
    // Actually usually inserted into BatchItem with specific tag, or just as
    // payload. Spec says Locate Request Payload is a Structure.

    if (maximumItems_ > 0) {
      structure->asStructure()->add(
          Element::createInteger(tag::KMIP_TAG_MAXIMUM_ITEMS, maximumItems_)
      );
    }

    if (offsetItems_ > 0) {
      structure->asStructure()->add(
          Element::createInteger(tag::KMIP_TAG_OFFSET_ITEMS, offsetItems_)
      );
    }

    for (const auto &attr : attributes_) {
      // Tag for Attribute structure in list is Attribute (0x420008)
      structure->asStructure()->add(attr.toElement());
    }

    return structure;
  }

  LocateRequestPayload
      LocateRequestPayload::fromElement(std::shared_ptr<Element> element) {
    // Check if structure
    // Iterate children
    LocateRequestPayload req;
    const auto *s = element->asStructure();
    if (!s) {
      throw KmipException("Payload is not a structure");
    }

    for (const auto &child : s->items) {
      if (child->tag == tag::KMIP_TAG_MAXIMUM_ITEMS) {
        req.maximumItems_ = child->toInt();
      } else if (child->tag == tag::KMIP_TAG_OFFSET_ITEMS) {
        req.offsetItems_ = child->toInt();
      } else if (child->tag == tag::KMIP_TAG_ATTRIBUTE) {
        req.attributes_.push_back(Attribute::fromElement(child));
      }
    }
    return req;
  }

  // === LocateResponsePayload ===

  std::shared_ptr<Element> LocateResponsePayload::toElement() const {
    auto structure = Element::createStructure(tag::KMIP_TAG_RESPONSE_PAYLOAD);

    if (locatedItems_) {
      structure->asStructure()->add(
          Element::createInteger(tag::KMIP_TAG_LOCATED_ITEMS, *locatedItems_)
      );
    }

    for (const auto &id : uniqueIdentifiers_) {
      // Each ID is TextString with tag UNIQUE_IDENTIFIER
      structure->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, id)
      );
    }
    return structure;
  }

  LocateResponsePayload
      LocateResponsePayload::fromElement(std::shared_ptr<Element> element) {
    LocateResponsePayload resp;
    const auto *s = element->asStructure();
    if (!s) {
      throw KmipException("Response Payload is not a structure");
    }

    for (const auto &child : s->items) {
      if (child->tag == tag::KMIP_TAG_LOCATED_ITEMS) {
        resp.setLocatedItems(child->toInt());
      } else if (child->tag == tag::KMIP_TAG_UNIQUE_IDENTIFIER) {
        resp.uniqueIdentifiers_.push_back(child->toString());
      }
    }
    return resp;
  }

}  // namespace kmipcore
