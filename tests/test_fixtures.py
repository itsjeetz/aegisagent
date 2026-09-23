"""Acceptance tests verifying hidden payload extraction across all 11 formats (§5.1, §9.1, §12)."""

import pytest
from aegis.ingestion.registry import extract
from aegis.models import InputSource
from eval.fixture_factory import make

PAYLOAD = "INJECTION_ATTACK_VECTOR_PAYLOAD_99"


def test_html_hidden_payload_techniques():
    # 1. hidden_div
    html_div = make(PAYLOAD, "html", "hidden_div")
    _, segs = extract(html_div, source=InputSource.HTML)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in HTML hidden_div"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "display_none"

    # 2. comment
    html_comm = make(PAYLOAD, "html", "comment")
    _, segs = extract(html_comm, source=InputSource.HTML)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in HTML comment"
    assert found[0].origin == "comment"
    assert found[0].hidden_reason == "html_comment"

    # 3. offscreen
    html_off = make(PAYLOAD, "html", "offscreen")
    _, segs = extract(html_off, source=InputSource.HTML)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in HTML offscreen"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "offscreen"

    # 4. tiny_font
    html_tiny = make(PAYLOAD, "html", "tiny_font")
    _, segs = extract(html_tiny, source=InputSource.HTML)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in HTML tiny_font"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "tiny_font"

    # 5. meta_tag
    html_meta = make(PAYLOAD, "html", "meta_tag")
    _, segs = extract(html_meta, source=InputSource.HTML)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in HTML meta_tag"
    assert found[0].origin == "metadata"

    # 6. alt_text
    html_alt = make(PAYLOAD, "html", "alt_text")
    _, segs = extract(html_alt, source=InputSource.HTML)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in HTML alt_text"
    assert found[0].origin == "alt_text"


def test_pdf_hidden_payload_techniques():
    # 1. white_text
    pdf_white = make(PAYLOAD, "pdf", "white_text")
    _, segs = extract(pdf_white, source=InputSource.PDF)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in PDF white_text"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "white_text"

    # 2. tiny_text
    pdf_tiny = make(PAYLOAD, "pdf", "tiny_text")
    _, segs = extract(pdf_tiny, source=InputSource.PDF)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in PDF tiny_text"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "tiny_font"

    # 3. metadata
    pdf_meta = make(PAYLOAD, "pdf", "metadata")
    _, segs = extract(pdf_meta, source=InputSource.PDF)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in PDF metadata"
    assert found[0].origin == "metadata"

    # 4. annotation
    pdf_annot = make(PAYLOAD, "pdf", "annotation")
    _, segs = extract(pdf_annot, source=InputSource.PDF)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in PDF annotation"
    assert found[0].origin == "comment"


def test_docx_hidden_payload_techniques():
    # 1. hidden_run (vanish)
    docx_vanish = make(PAYLOAD, "docx", "hidden_run")
    _, segs = extract(docx_vanish, source=InputSource.DOCX)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in DOCX vanish run"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "vanish"

    # 2. white_text
    docx_white = make(PAYLOAD, "docx", "white_text")
    _, segs = extract(docx_white, source=InputSource.DOCX)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in DOCX white_text"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "white_text"

    # 3. comment
    docx_comm = make(PAYLOAD, "docx", "comment")
    _, segs = extract(docx_comm, source=InputSource.DOCX)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in DOCX comment"
    assert found[0].origin == "comment"


def test_email_hidden_payload_techniques():
    # 1. header_field
    eml_header = make(PAYLOAD, "email", "header_field")
    _, segs = extract(eml_header, source=InputSource.EMAIL)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Email header"
    assert found[0].origin == "header"

    # 2. quoted_thread
    eml_quote = make(PAYLOAD, "email", "quoted_thread")
    _, segs = extract(eml_quote, source=InputSource.EMAIL)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Email quoted_thread"
    assert found[0].origin == "comment"
    assert found[0].hidden_reason == "quoted_thread"

    # 3. html_hidden
    eml_html = make(PAYLOAD, "email", "html_hidden")
    _, segs = extract(eml_html, source=InputSource.EMAIL)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Email html_hidden"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "display_none"

    # 4. attachment
    eml_att = make(PAYLOAD, "email", "attachment")
    _, segs = extract(eml_att, source=InputSource.EMAIL)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Email attachment"


def test_markdown_hidden_payload_techniques():
    # 1. comment
    md_comm = make(PAYLOAD, "markdown", "comment")
    _, segs = extract(md_comm, source=InputSource.MARKDOWN)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Markdown comment"
    assert found[0].origin == "comment"
    assert found[0].hidden_reason == "html_comment"

    # 2. link_title
    md_link = make(PAYLOAD, "markdown", "link_title")
    _, segs = extract(md_link, source=InputSource.MARKDOWN)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Markdown link_title"
    assert found[0].origin == "alt_text"

    # 3. image_alt
    md_alt = make(PAYLOAD, "markdown", "image_alt")
    _, segs = extract(md_alt, source=InputSource.MARKDOWN)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Markdown image_alt"
    assert found[0].origin == "alt_text"

    # 4. inline_html
    md_html = make(PAYLOAD, "markdown", "inline_html")
    _, segs = extract(md_html, source=InputSource.MARKDOWN)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Markdown inline_html"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "display_none"


def test_api_response_payload_techniques():
    # 1. nested_value
    api_val = make(PAYLOAD, "api_response", "nested_value")
    _, segs = extract(api_val, source=InputSource.API_RESPONSE)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in API nested_value"
    assert found[0].origin == "json_value"

    # 2. key_name
    api_key = make(PAYLOAD, "api_response", "key_name")
    _, segs = extract(api_key, source=InputSource.API_RESPONSE)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in API key_name"
    assert found[0].origin == "json_key"

    # 3. metadata_field (XML)
    api_xml = make(PAYLOAD, "api_response", "metadata_field")
    _, segs = extract(api_xml, source=InputSource.API_RESPONSE)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in XML metadata_field"
    assert found[0].origin == "json_value"


def test_source_code_payload_techniques():
    # 1. comment
    code_comm = make(PAYLOAD, "source_code", "comment")
    _, segs = extract(code_comm, source=InputSource.SOURCE_CODE, filename="module.py")
    found = [s for s in segs if PAYLOAD in s.text and s.origin == "code_comment"]
    assert found, "Payload not found in code comment"
    assert found[0].origin == "code_comment"

    # 2. docstring
    code_doc = make(PAYLOAD, "source_code", "docstring")
    _, segs = extract(code_doc, source=InputSource.SOURCE_CODE, filename="module.py")
    found = [s for s in segs if PAYLOAD in s.text and s.origin == "string_literal"]
    assert found, "Payload not found in code docstring"
    assert found[0].origin == "string_literal"

    # 3. string_literal
    code_str = make(PAYLOAD, "source_code", "string_literal")
    _, segs = extract(code_str, source=InputSource.SOURCE_CODE, filename="module.py")
    found = [s for s in segs if PAYLOAD in s.text and s.origin == "string_literal"]
    assert found, "Payload not found in code string literal"
    assert found[0].origin == "string_literal"


def test_ocr_text_and_image_exif():
    # OCR text confusable chars
    ocr_raw = make("delete my secret", "ocr_text", "confusable_chars")
    _, segs = extract(ocr_raw, source=InputSource.OCR_TEXT)
    assert any(s.origin == "ocr" for s in segs)

    # Image EXIF comment
    img_exif = make(PAYLOAD, "image", "exif_comment")
    _, segs = extract(img_exif, source=InputSource.IMAGE)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in Image EXIF"
    assert found[0].origin == "exif"


def test_user_message_and_web_page():
    # User message
    msg = make(PAYLOAD, "user_message", "direct")
    _, segs = extract(msg, source=InputSource.USER_MESSAGE)
    assert segs[0].origin == "visible"
    assert segs[0].text == PAYLOAD

    # Web page hidden div
    web = make(PAYLOAD, "web_page", "hidden_div")
    _, segs = extract(web, source=InputSource.WEB_PAGE)
    found = [s for s in segs if PAYLOAD in s.text]
    assert found, "Payload not found in web_page hidden_div"
    assert found[0].origin == "hidden"
    assert found[0].hidden_reason == "display_none"
