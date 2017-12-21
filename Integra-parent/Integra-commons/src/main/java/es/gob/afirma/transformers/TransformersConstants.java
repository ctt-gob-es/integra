// Copyright (C) 2012-13 MINHAP, Gobierno de España
// This program is licensed and may be used, modified and redistributed under the terms
// of the European Public License (EUPL), either version 1.1 or (at your
// option) any later version as soon as they are approved by the European Commission.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and
// more details.
// You should have received a copy of the EUPL1.1 license
// along with this program; if not, you may find it at
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.transformers.TransformersConstants.java.</p>
 * <b>Description:</b><p>Interface that defines constants related to the generation of request messages to @Firma, TS@ and eVisor, and related
 * to the processing of responses messages from those platforms.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>25/03/2011.</p>
 * @author Gobierno de España.
 * @version 1.0, 25/03/2011.
 */
package es.gob.afirma.transformers;

/**
 * <p>Interface that defines constants related to the generation of request messages to @Firma, TS@ and eVisor, and related
 * to the processing of responses messages from those platforms.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * @version 1.0, 17/03/2011.
 */
public interface TransformersConstants {

    /**
     * Constant attribute that represents name of API transformers's configuration file.
     */
    String TRANSFORMERS_FILE_PROPERTIES = "transformers.properties";

    /**
     * Constant attribute that represents file of parsed parameter names.
     */
    String PARSED_PARAMETERS_FILE = "parserParameters.properties";

    /**
     * Constant attribute that represents property name that indicates transformers templates path.
     */
    String TRANSFORMERS_TEMPLATES_PATH_PROPERTIES = "TransformersTemplatesPath";

    /**
     * Constant attribute that represents the 'request' type to generate XML interface.
     */
    String REQUEST_CTE = "request";

    /**
     * Constant attribute that represents the 'response' type to generate XML interface.
     */
    String RESPONSE_CTE = "response";

    /**
     * Constant attribute that represents the 'parser' value.
     */
    String PARSER_CTE = "parser";

    /**
     * Constant attribute that represents property that indicates transformers class.
     */
    String TRANSFORMER_CLASS_CTE = "transformerClass";

    /**
     * Constant attribute that represents property that indicates template name.
     */
    String TEMPLATE_CTE = "template";

    /**
     * Constant attribute that represents property for indicate root node to parse.
     */
    String RESP_ROOT_ELEMENT_CTE = "rootElement";

    /**
     * Constant attribute that represents the message version 1.0.
     */
    String VERSION_10 = "1_0";

    /**
     * Constant attribute that represents schema location address tag from a message.
     */
    String SCHEMA_LOCATION_ADDRESS_PROP = "schemaLocationAddress";

    /**
     * Constant attribute that represents attribute to replace xsi:SchemaLocation from tag message.
     */
    String SCH_LOC_ADD_SEP = "_XXX_";

    /**
     * Constant attribute that represents the separator used for attributes in XML nodes.
     */
    String ATTRIBUTE_SEPARATOR = "@";

    /**
     * Constant attribute that represents the separator used for types and values in XML nodes.
     */
    String TYPES_VALUES_SEPARATOR = "#";

    /**
     * Constant attribute that represents the separator used for several names in XML nodes.
     */
    String SEVERAL_SEPARATOR = ",";

    /**
     * Constant attribute that represents name of attribute used for @Firma node type.
     */
    String ATTR_XML_NODE_TYPE = "afirmaNodeType";

    /**
     * Constant attribute used to indicate the name of several occurrences nodes (separated by coma)  to be retrieved from the message to parse.
     */
    String ATTR_XML_OCURRENCE_NAMES = "ocurrenceNames";

    /**
     * Constant attribute used to indicate the attributes (separated by coma)  to be retrieved from the message to parse.
     */
    String ATTRIBUTES_TO_RETRIEVE = "attributesToInclude";

    /**
     * Constant attribute that represents @Firma node type used for map field keys.
     */
    String ANODE_TYPE_FIELD_KEY = "mapFieldKey";

    /**
     * Constant attribute that represents @Firma node type used for map field values.
     */
    String ANODE_TYPE_FIELD_VALUE = "mapFieldValue";

    /**
     * Constant attribute that represents @Firma node type used for map fields.
     */
    String ANODE_TYPE_MAP_FIELDS = "mapFields";

    /**
     * Constant attribute that represents @Firma node type used for text nodes.
     */
    String ANODE_TYPE_TEXT = "text";

    /**
     * Constant attribute that represents @Firma node type used for attributes.
     */
    String ANODE_TYPE_ATTRIBUTE = "attribute";

    /**
     * Constant attribute that represents @Firma node type used for choice nodes.
     */
    String ANODE_TYPE_CHOICE = "choice";

    /**
     * Constant attribute that represents @Firma node type used optional nodes.
     */
    String ANODE_TYPE_OPTIONAL = "optional";

    /**
     * Constant attribute that represents @Firma node type used for several nodes.
     */
    String ANODE_TYPE_SERVERAL = "severalOcurrences";

    /**
     * Constant attribute that represents @Firma node type used for nodes with text and attributes.
     */
    String ANODE_TYPE_ATTR_TEXT = "attributeText";

    /**
     * Constant attribute that represents the @Firma node type used for XML nodes (node of type Element).
     */
    String ANODE_TYPE_XML = "xml";

    /**
     * Constant attribute that represents optional @Firma node types.
     */
    String[ ] OPTIONAL_ANODE_TYPES = { ANODE_TYPE_CHOICE, ANODE_TYPE_OPTIONAL };

}
