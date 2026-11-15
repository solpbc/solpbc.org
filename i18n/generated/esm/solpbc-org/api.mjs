// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { FluentBundle, FluentResource } from "../vendor/fluent-bundle/index.js";
import { CATALOGS } from "./catalogs.mjs";

export function cardinal(val) { return { type: "cardinal", value: val }; }
export function integer(val) { return { type: "integer", value: val }; }

const LOCALES = {
  "en-US": { bundleLocale: "en-US", cardinal: "en" },
};

const CATEGORIES = {
  "en": (n) => (n == 1) ? "one" : "other",
};

const MESSAGES = {
  "solpbc.site.brands.badgelabelsbodytext": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e62616467656c6162656c73626f647974657874",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.badgesocialopensource": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6261646765736f6369616c6f70656e736f75726365",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.badgetextmarkdark": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6261646765746578746d61726b6461726b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.badgevitenabled": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6261646765766974656e61626c6564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.badgevitenabledflat": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6261646765766974656e61626c6564666c6174",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.badgeviticononly": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e626164676576697469636f6e6f6e6c79",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.boxed": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e626f786564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.brand": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6272616e64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.brands": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6272616e6473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.brandsolpbc": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6272616e64736f6c706263",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.callaction": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e63616c6c616374696f6e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.clearspace8": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636c656172737061636538",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.clearspacedotwidth": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636c6561727370616365646f747769647468",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.clearspaceminimumsize": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636c65617273706163656d696e696d756d73697a65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.coloreddarkbackgroundsshownvitgreen": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f6c6f7265646461726b6261636b67726f756e647373686f776e766974677265656e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.colors": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f6c6f7273",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.companymarkfullcolorlight": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f6d70616e796d61726b66756c6c636f6c6f726c69676874",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.constvitmarkvv": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f6e73747669746d61726b7676",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.copy": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f7079",
    formatIntent: "enum",
    selectorVar: "state",
    enumValues: ["idle", "done", "manual"],
    enumDefault: "idle",
    variantKeys: {
      "idle": "m736f6c7062632e736974652e6272616e64732e636f7079_v69646c65",
      "done": "m736f6c7062632e736974652e6272616e64732e636f7079_v646f6e65",
      "manual": "m736f6c7062632e736974652e6272616e64732e636f7079_v6d616e75616c",
    },
    defaultKey: "m736f6c7062632e736974652e6272616e64732e636f7079_v69646c65",
    arguments: [
      { name: "state", type: "string", min: null, max: null, numericStyle: "ungrouped" },
    ],
  },
  "solpbc.site.brands.copyconstant": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f7079636f6e7374616e74",
    formatIntent: "enum",
    selectorVar: "state",
    enumValues: ["idle", "done", "manual"],
    enumDefault: "idle",
    variantKeys: {
      "idle": "m736f6c7062632e736974652e6272616e64732e636f7079636f6e7374616e74_v69646c65",
      "done": "m736f6c7062632e736974652e6272616e64732e636f7079636f6e7374616e74_v646f6e65",
      "manual": "m736f6c7062632e736974652e6272616e64732e636f7079636f6e7374616e74_v6d616e75616c",
    },
    defaultKey: "m736f6c7062632e736974652e6272616e64732e636f7079636f6e7374616e74_v69646c65",
    arguments: [
      { name: "state", type: "string", min: null, max: null, numericStyle: "ungrouped" },
    ],
  },
  "solpbc.site.brands.copyfailed": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f70796661696c6564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.copyhex": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f7079686578",
    formatIntent: "text",
    arguments: [
      { name: "hex", type: "string", min: null, max: null, numericStyle: "ungrouped" },
    ],
  },
  "solpbc.site.brands.copysvg": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f7079737667",
    formatIntent: "enum",
    selectorVar: "state",
    enumValues: ["idle", "done", "manual"],
    enumDefault: "idle",
    variantKeys: {
      "idle": "m736f6c7062632e736974652e6272616e64732e636f7079737667_v69646c65",
      "done": "m736f6c7062632e736974652e6272616e64732e636f7079737667_v646f6e65",
      "manual": "m736f6c7062632e736974652e6272616e64732e636f7079737667_v6d616e75616c",
    },
    defaultKey: "m736f6c7062632e736974652e6272616e64732e636f7079737667_v69646c65",
    arguments: [
      { name: "state", type: "string", min: null, max: null, numericStyle: "ungrouped" },
    ],
  },
  "solpbc.site.brands.copyvcopiesliteraltwocodepointstringv": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f707976636f706965736c69746572616c74776f636f6465706f696e74737472696e6776",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.copyvitmark": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e636f70797669746d61726b",
    formatIntent: "enum",
    selectorVar: "state",
    enumValues: ["idle", "done", "manual"],
    enumDefault: "idle",
    variantKeys: {
      "idle": "m736f6c7062632e736974652e6272616e64732e636f70797669746d61726b_v69646c65",
      "done": "m736f6c7062632e736974652e6272616e64732e636f70797669746d61726b_v646f6e65",
      "manual": "m736f6c7062632e736974652e6272616e64732e636f70797669746d61726b_v6d616e75616c",
    },
    defaultKey: "m736f6c7062632e736974652e6272616e64732e636f70797669746d61726b_v69646c65",
    arguments: [
      { name: "state", type: "string", min: null, max: null, numericStyle: "ungrouped" },
    ],
  },
  "solpbc.site.brands.darkbackgrounds": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6461726b6261636b67726f756e6473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.darkmodehover": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6461726b6d6f6465686f766572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.definedhexdigitalfirstnopantonedesignvit": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646566696e65646865786469676974616c66697273746e6f70616e746f6e6564657369676e766974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.diecutstickernearblack": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646965637574737469636b65726e656172626c61636b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.diecutstickeropensourceissocialwhite": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646965637574737469636b65726f70656e736f757263656973736f6369616c7768697465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dodont": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f646f6e74",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontboxed": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e74626f786564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.donteffected": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e746566666563746564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontmodifymarksnorecoloringexceptaccessibilit": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e746d6f646966796d61726b736e6f7265636f6c6f72696e676578636570746163636573736962696c6974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontproportionchanged": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e7470726f706f7274696f6e6368616e676564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontrecolored": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e747265636f6c6f726564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontrotated": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e74726f7461746564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontshadowed": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e74736861646f776564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontstretched": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e74737472657463686564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontuseourmarksornamesimply": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e747573656f75726d61726b736f726e616d6573696d706c79",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.dontusethemasyourownproduct": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f6e747573657468656d6173796f75726f776e70726f64756374",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.download": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f776e6c6f6164",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.downloadallsolpbceveryvariantfullsize": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f776e6c6f6164616c6c736f6c706263657665727976617269616e7466756c6c73697a65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.downloadallvitmarkswordmarkbadgesfullsize": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f776e6c6f6164616c6c7669746d61726b73776f72646d61726b62616467657366756c6c73697a65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.downloadeverything": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f776e6c6f616465766572797468696e67",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.downloadeverythingeverysolpbcandvitasset": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e646f776e6c6f616465766572797468696e676576657279736f6c706263616e647669746173736574",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.effected": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6566666563746564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.enabled": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e656e61626c6564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.extro": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e657874726f",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.extroissolpbcsaicofounder": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e657874726f6973736f6c706263736169636f666f756e646572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.fewthingsprotectpeoplewhotrustthesenames": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6665777468696e677370726f7465637470656f706c6577686f747275737474686573656e616d6573",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.ffffff": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e666666666666",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.flatnogradient": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e666c61746e6f6772616469656e74",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.foundations": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e666f756e646174696f6e73",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.gradient": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6772616469656e74",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.hex": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e686578",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.highcontrasttextwhite": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e68696768636f6e7472617374746578747768697465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.iconbadge": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e69636f6e6261646765",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.joinbazaar": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6a6f696e62617a616172",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.lightergreendarkbackgrounds": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6c696768746572677265656e6461726b6261636b67726f756e6473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.logoscolorsandwordsforsolpbcandvitan": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6c6f676f73636f6c6f7273616e64776f726473666f72736f6c706263616e64766974616e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.logoscolorsandwordsforsolpbcandvitno": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6c6f676f73636f6c6f7273616e64776f726473666f72736f6c706263616e647669746e6f",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.logoscolorsandwordsforsolpbcandvitso": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6c6f676f73636f6c6f7273616e64776f726473666f72736f6c706263616e64766974736f",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.logoswordmarks": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6c6f676f73776f72646d61726b73",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.markfullcolorlight": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6d61726b66756c6c636f6c6f726c69676874",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.markissunringnamesetinsideit": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6d61726b697373756e72696e676e616d65736574696e736964656974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.markisvreadsasoneword": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6d61726b697376726561647361736f6e65776f7264",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.minimum16pxmarkonlyclearspaceleastwidth": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6d696e696d756d313670786d61726b6f6e6c79636c65617273706163656c656173747769647468",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.minimum32pxclearspaceleast8displayedsize": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6d696e696d756d33327078636c65617273706163656c6561737438646973706c6179656473697a65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n059669": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e303539363639",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n06d6a0": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e303664366130",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n2026solpbcsolpbcorgprivacycontact": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e32303236736f6c706263736f6c7062636f726770726976616379636f6e74616374",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n255255255": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e323535323535323535",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n333333": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e333333333333",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n34d399": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e333464333939",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n5150105": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e35313530313035",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n515151": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e353135313531",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n52211153": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e3532323131313533",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.n6214160": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e36323134313630",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.name": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e616d65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.nameisintentionaloppositeintroextroisoutward": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e616d656973696e74656e74696f6e616c6f70706f73697465696e74726f657874726f69736f757477617264",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.notsurejustasktherescontactform": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6e6f74737572656a75737461736b746865726573636f6e74616374666f726d",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.onesentence": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6f6e6573656e74656e6365",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.opensource": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6f70656e736f75726365",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.opensourceissocial": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6f70656e736f757263656973736f6369616c",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.opensourceissocialbadge": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e6f70656e736f757263656973736f6369616c6261646765",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.pbcwordmark": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e706263776f72646d61726b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.pbcwordmarkblack": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e706263776f72646d61726b626c61636b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.pbcwordmarkwhite": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e706263776f72646d61726b7768697465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.pdf": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e706466",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.png1024": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e706e6731303234",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.png512": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e706e67353132",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.primarymarkbadgesaccents": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7072696d6172796d61726b626164676573616363656e7473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.primarymarklight": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7072696d6172796d61726b6c69676874",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.proportionchanged": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e70726f706f7274696f6e6368616e676564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.readmebadges": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e726561646d65626164676573",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.readmemarkdown": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e726561646d656d61726b646f776e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.recolored": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7265636f6c6f726564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.rgb": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e726762",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.rotated": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e726f7461746564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.shadowed": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736861646f776564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.singlecolorblackprintlimitedcolor": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e73696e676c65636f6c6f72626c61636b7072696e746c696d69746564636f6c6f72",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.skipcontent": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736b6970636f6e74656e74",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.slate": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736c617465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.slogans": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736c6f67616e73",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.social": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6369616c",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbc32pixels": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c7062633332706978656c73",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbcclearspacediagram": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c706263636c65617273706163656469616772616d",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbcisacoloradopublicbenefitcorporation": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c706263697361636f6c6f7261646f7075626c696362656e65666974636f72706f726174696f6e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbcpublicbenefitcorporationbehindsolstonev": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c7062637075626c696362656e65666974636f72706f726174696f6e626568696e64736f6c73746f6e6576",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbcsolstonevitaretrademarkssolpbc": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c706263736f6c73746f6e6576697461726574726164656d61726b73736f6c706263",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbcwordmark": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c706263776f72646d61726b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbcwordmarkblack": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c706263776f72646d61726b626c61636b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solpbcwordmarkwhite": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c706263776f72646d61726b7768697465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solstone": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c73746f6e65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solstonemarkalt": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c73746f6e656d61726b616c74",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solstonemarkelement1": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c73746f6e656d61726b656c656d656e7431",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.solstonemarkelement2": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e736f6c73746f6e656d61726b656c656d656e7432",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.stickerlockup": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e737469636b65726c6f636b7570",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.stretched": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e737472657463686564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.svg": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e737667",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.tagline": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7461676c696e65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.textwhiteusevitgreendeep059669brighter": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e746578747768697465757365766974677265656e646565703035393636396272696768746572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.thatswholestanceitssamestance": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e746861747377686f6c657374616e636569747373616d657374616e6365",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.thecompanywordmarksharessolstonesbeamsri": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e746865636f6d70616e79776f72646d61726b736861726573736f6c73746f6e65736265616d737269",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.theseassetsarefreeusepresswritingabout": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e746865736561737365747361726566726565757365707265737377726974696e6761626f7574",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.thesolstonemarklockupsappiconcolorsand": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e746865736f6c73746f6e656d61726b6c6f636b75707361707069636f6e636f6c6f7273616e64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.thispageloadsnothinganyoneelsesserver": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e74686973706167656c6f6164736e6f7468696e67616e796f6e65656c736573736572766572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.twotypefacescomfortaadisplayintertextbothare": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e74776f747970656661636573636f6d666f72746161646973706c6179696e74657274657874626f7468617265",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.use": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e757365",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.using": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7573696e67",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.usingthese": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7573696e677468657365",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.v": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e76",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vit": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vit16pixels": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669743136706978656c73",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitclearspacediagram": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974636c65617273706163656469616772616d",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitenabledbadge": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974656e61626c65646261646765",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitenabledbadgeflat": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974656e61626c65646261646765666c6174",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitenabledhttpsvitorgbadgevit": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974656e61626c656468747470737669746f72676261646765766974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitgreen": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974677265656e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitgreendeep": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974677265656e64656570",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitgreenlight": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974677265656e6c69676874",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.viticononlybadge": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e76697469636f6e6f6e6c796261646765",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitishowsolstonegetsbettereveryoneopen": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746973686f77736f6c73746f6e656765747362657474657265766572796f6e656f70656e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitlockupstickerblack": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746c6f636b7570737469636b6572626c61636b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitlockupstickerwhite": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746c6f636b7570737469636b65727768697465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmark": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmark2": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b32",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkblack": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b626c61636b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkblack2": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b626c61636b32",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkdarkbackground": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b6461726b6261636b67726f756e64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkdarkbackground2": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b6461726b6261636b67726f756e6432",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkislowercasevdotaboveit": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b69736c6f7765726361736576646f7461626f76656974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkwhite": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b7768697465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkwhite2": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b776869746532",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitmarkwhitevitgreen": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746d61726b7768697465766974677265656e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitopensourceissocial": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7669746f70656e736f757263656973736f6369616c",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitsocialnetworksharingsoftwarecapabilitiesope": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974736f6369616c6e6574776f726b73686172696e67736f6674776172656361706162696c69746965736f7065",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitwordmark": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974776f72646d61726b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitwordmark2": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974776f72646d61726b32",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitwordmarkblack": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974776f72646d61726b626c61636b",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vitwordmarkblack2": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e766974776f72646d61726b626c61636b32",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vtextmarklabel": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e76746578746d61726b6c6162656c",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.vvitmarkterminalsclisreadmesunicodeu": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e767669746d61726b7465726d696e616c73636c6973726561646d6573756e69636f646575",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.white": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e7768697465",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.why": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e776879",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.wordmarkovertaglineassquarediecutsticker": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e776f72646d61726b6f7665727461676c696e656173737175617265646965637574737469636b6572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.brands.writingextrolowercaserunningtexttoolnamesextr": {
    resourceKey: "m736f6c7062632e736974652e6272616e64732e77726974696e67657874726f6c6f7765726361736572756e6e696e6774657874746f6f6c6e616d657365787472",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.articles": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e61727469636c6573",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.blog": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e626c6f67",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.bylaws": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e62796c617773",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.contact": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e636f6e74616374",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.n2026solpbcsolpbcorgprivacybylawsarticles": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e6e32303236736f6c706263736f6c7062636f72677072697661637962796c61777361727469636c6573",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.privacy": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e70726976616379",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.solpbc": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e736f6c706263",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.chrome.solpbcorg": {
    resourceKey: "m736f6c7062632e736974652e6368726f6d652e736f6c7062636f7267",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.aiisusedscreenyourmessage": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e616969737573656473637265656e796f75726d657373616765",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.backsolpbcorg": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e6261636b736f6c7062636f7267",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.checkthatyourehumandidntgo": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e636865636b74686174796f75726568756d616e6469646e74676f",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.contactsolpbc": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e636f6e74616374736f6c706263",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.gettouch": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e676574746f756368",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.gettouchsolpbcyourmessagegoesjer": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e676574746f756368736f6c706263796f75726d657373616765676f65736a6572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.internalerror": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e696e7465726e616c6572726f72",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.invalidrequestbody": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e696e76616c696472657175657374626f6479",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.lotmessagescameherejustnowpleasewait": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e6c6f746d6573736167657363616d65686572656a7573746e6f77706c6561736577616974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.messageisrequired": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e6d65737361676569737265717569726564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.messagesent": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e6d65737361676573656e74",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.messagesentsolpbc": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e6d65737361676573656e74736f6c706263",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.send": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e73656e64",
    formatIntent: "enum",
    selectorVar: "state",
    enumValues: ["idle", "sending"],
    enumDefault: "idle",
    variantKeys: {
      "idle": "m736f6c7062632e736974652e636f6e746163742e73656e64_v69646c65",
      "sending": "m736f6c7062632e736974652e636f6e746163742e73656e64_v73656e64696e67",
    },
    defaultKey: "m736f6c7062632e736974652e636f6e746163742e73656e64_v69646c65",
    arguments: [
      { name: "state", type: "string", min: null, max: null, numericStyle: "ungrouped" },
    ],
  },
  "solpbc.site.contact.solpbcdoesnttrackyoudoesnt": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e736f6c706263646f65736e74747261636b796f75646f65736e74",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.submissionrejected": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e7375626d697373696f6e72656a6563746564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.thanksreachingoutjerwillgetbackyou": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e7468616e6b737265616368696e676f75746a657277696c6c6765746261636b796f75",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.thatdidntsendpleasetryagainor": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e746861746469646e7473656e64706c65617365747279616761696e6f72",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.toomanyrequests": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e746f6f6d616e797265717565737473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.validemailisrequired": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e76616c6964656d61696c69737265717569726564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.verificationfailed": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e766572696669636174696f6e6661696c6564",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.whatsyourmind": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e7768617473796f75726d696e64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.youremail": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e796f7572656d61696c",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.yourmessagegoesjernoticketingsystemno": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e796f75726d657373616765676f65736a65726e6f7469636b6574696e6773797374656d6e6f",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.yourmessagehasbeensentsolpbc": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e796f75726d6573736167656861736265656e73656e74736f6c706263",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.contact.yourname": {
    resourceKey: "m736f6c7062632e736974652e636f6e746163742e796f75726e616d65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.afterjerceasesserveasdirectorcovenantscan": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e61667465726a6572636561736573736572766561736469726563746f72636f76656e616e747363616e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.anymergeracquisitionortransfercontroliscondit": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e616e796d65726765726163717569736974696f6e6f727472616e73666572636f6e74726f6c6973636f6e646974",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.continuitybeyondfounder": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e636f6e74696e756974796265796f6e64666f756e646572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.duringjersstewardshipasdirectorcompanys": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e647572696e676a657273737465776172647368697061736469726563746f72636f6d70616e7973",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.foundedjeremiemiller": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e666f756e6465646a6572656d69656d696c6c6572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.foundedsolelyoperatedjeremiemiller": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e666f756e646564736f6c656c796f706572617465646a6572656d69656d696c6c6572",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.founderstewardship": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e666f756e6465727374657761726473686970",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.governancecommitments": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e676f7665726e616e6365636f6d6d69746d656e7473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.ifjerceasesserveasdirectorresultingboard": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e69666a6572636561736573736572766561736469726563746f72726573756c74696e67626f617264",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.missionalignedsuccessorsonly": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e6d697373696f6e616c69676e6564737563636573736f72736f6e6c79",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.n2026solpbcsolpbcorgprivacybylawsarticles": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e6e32303236736f6c706263736f6c7062636f72677072697661637962796c61777361727469636c6573",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.publicbenefitcorporationbindingchartercovenants": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e7075626c696362656e65666974636f72706f726174696f6e62696e64696e6763686172746572636f76656e616e7473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.readarticlesincorporationreadbylawsamendedrest": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e7265616461727469636c6573696e636f72706f726174696f6e7265616462796c617773616d656e64656472657374",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.readourblog": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e726561646f7572626c6f67",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.rookeryopensourcepdsaiagentscloudflarenative": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e726f6f6b6572796f70656e736f7572636570647361696167656e7473636c6f7564666c6172656e6174697665",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.solpbcdigitalselfdetermination": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e736f6c7062636469676974616c73656c6664657465726d696e6174696f6e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.solpbclogo": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e736f6c7062636c6f676f",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.solpbcpublicbenefitcorporationadvancingdigital": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e736f6c7062637075626c696362656e65666974636f72706f726174696f6e616476616e63696e676469676974616c",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.solpbcwillneverselllicensesublicenseor": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e736f6c70626377696c6c6e6576657273656c6c6c6963656e73657375626c6963656e73656f72",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.solstoneisapersonaljournalplatformthesol": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e736f6c73746f6e65697361706572736f6e616c6a6f75726e616c706c6174666f726d746865736f6c",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.specificpublicbenefitpurposecorporationisadvan": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e73706563696669637075626c696362656e65666974707572706f7365636f72706f726174696f6e6973616476616e",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.strengtheningonly": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e737472656e677468656e696e676f6e6c79",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.thesecommitmentsarelegallybindingfiledcolorado": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e7468657365636f6d6d69746d656e74736172656c6567616c6c7962696e64696e6766696c6564636f6c6f7261646f",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.trysolstone": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e747279736f6c73746f6e65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.vitsocialcapabilitynetworkwheredevelopersaiag": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e766974736f6369616c6361706162696c6974796e6574776f726b7768657265646576656c6f7065727361696167",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.wealsobuild": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e7765616c736f6275696c64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.whatwemake": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e7768617477656d616b65",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.wikipediablueskylinkedincontact": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e77696b697065646961626c7565736b796c696e6b6564696e636f6e74616374",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.home.yourdataisneversold": {
    resourceKey: "m736f6c7062632e736974652e686f6d652e796f75726461746169736e65766572736f6c64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.backsolpbcorg": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e6261636b736f6c7062636f7267",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.brandassets": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e6272616e64617373657473",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.contactus": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e636f6e746163747573",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.n2026solpbcyourdataisneversold": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e6e32303236736f6c706263796f75726461746169736e65766572736f6c64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.pagenotfound": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e706167656e6f74666f756e64",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.pagenotfoundsolpbc": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e706167656e6f74666f756e64736f6c706263",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.readblog": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e72656164626c6f67",
    formatIntent: "text",
    arguments: [
    ],
  },
  "solpbc.site.missing.thispagedoesntexistbuteverythingsol": {
    resourceKey: "m736f6c7062632e736974652e6d697373696e672e7468697370616765646f65736e74657869737462757465766572797468696e67736f6c",
    formatIntent: "text",
    arguments: [
    ],
  },
};

const BUNDLES = new Map();

function getBundle(locale, useIsolating) {
  const cacheKey = `${locale}:${useIsolating}`;
  let bundle = BUNDLES.get(cacheKey);
  if (!bundle) {
    const locInfo = LOCALES[locale];
    if (!locInfo) throw new Error(`Unknown locale: ${locale}`);
    const ftlSource = CATALOGS[locale];
    if (ftlSource === undefined) throw new Error(`Unknown catalog: ${locale}`);
    const resource = new FluentResource(ftlSource);
    bundle = new FluentBundle(locInfo.bundleLocale, { useIsolating });
    const errors = bundle.addResource(resource);
    if (errors.length > 0) throw new Error(`FTL errors: ${errors.join(", ")}`);
    BUNDLES.set(cacheKey, bundle);
  }
  return bundle;
}

export function render(locale, messageId, args = [], { useIsolating = true } = {}) {
  if (typeof useIsolating !== "boolean") throw new Error("Expected boolean useIsolating");
  const locInfo = LOCALES[locale];
  if (!locInfo) throw new Error(`Unknown locale: ${locale}`);

  const msgInfo = MESSAGES[messageId];
  if (!msgInfo) throw new Error(`Unknown message: ${messageId}`);

  const seen = new Set();
  for (const [k] of args) {
    if (seen.has(k)) throw new Error(`Duplicate argument: ${k}`);
    seen.add(k);
  }

  const declaredMap = new Map(msgInfo.arguments.map(a => [a.name, a]));
  for (const [k] of args) {
    if (!declaredMap.has(k)) throw new Error(`Unknown argument: ${k}`);
  }
  for (const k of declaredMap.keys()) {
    if (!seen.has(k)) throw new Error(`Missing argument: ${k}`);
  }

  const fArgs = {};
  let selectedVariant = msgInfo.enumDefault || null;

  for (const [k, v] of args) {
    const spec = declaredMap.get(k);
    if (spec.type === "string") {
      if (typeof v !== "string") throw new Error(`Expected string for ${k}`);
      if (msgInfo.formatIntent === "enum" && msgInfo.selectorVar === k) {
        if (msgInfo.enumValues.includes(v)) {
          selectedVariant = v;
        } else {
          selectedVariant = msgInfo.enumDefault;
        }
      }
      fArgs[k] = v;
    } else if (spec.type === "boolean") {
      if (typeof v !== "boolean") throw new Error(`Expected boolean for ${k}`);
      fArgs[k] = v ? "true" : "false";
    } else if (spec.type === "integer") {
      if (v && typeof v === "object" && v.type === "cardinal") throw new Error(`Expected integer, got cardinal for ${k}`);
      const num = (v && typeof v === "object" && v.type === "integer") ? v.value : v;
      if (typeof num !== "number" && typeof num !== "bigint") throw new Error(`Expected number for ${k}`);
      if (typeof num === "number" && (!Number.isFinite(num) || !Number.isInteger(num))) throw new Error(`Expected integer number for ${k}`);
      const nVal = BigInt(num);
      const minVal = spec.min !== null ? BigInt(spec.min) : -9007199254740991n;
      const maxVal = spec.max !== null ? BigInt(spec.max) : 9007199254740991n;
      const effMin = minVal < -9007199254740991n ? -9007199254740991n : minVal;
      const effMax = maxVal > 9007199254740991n ? 9007199254740991n : maxVal;
      if (nVal < effMin || nVal > effMax) throw new Error(`Out of range for ${k}`);
      fArgs[k] = Number(nVal);
    } else if (spec.type === "cardinal") {
      if (v && typeof v === "object" && v.type === "integer") throw new Error(`Expected cardinal, got integer for ${k}`);
      const num = (v && typeof v === "object" && v.type === "cardinal") ? v.value : v;
      if (typeof num !== "number" && typeof num !== "bigint") throw new Error(`Expected number for ${k}`);
      if (typeof num === "number" && (!Number.isFinite(num) || !Number.isInteger(num))) throw new Error(`Expected integer number for ${k}`);
      const nVal = BigInt(num);
      const minVal = spec.min !== null ? BigInt(spec.min) : -2147483648n;
      const maxVal = spec.max !== null ? BigInt(spec.max) : 2147483647n;
      const effMin = minVal < -2147483648n ? -2147483648n : minVal;
      const effMax = maxVal > 2147483647n ? 2147483647n : maxVal;
      if (nVal < effMin || nVal > effMax) throw new Error(`Out of range for ${k}`);
      fArgs[k] = Number(nVal);
    }
  }

  if (msgInfo.formatIntent === "cardinal") {
    const select = CATEGORIES[locInfo.cardinal];
    fArgs.i18nCategory = select ? select(Math.abs(fArgs[msgInfo.selectorVar])) : "other";
  }

  const bundle = getBundle(locale, useIsolating);

  const targetKey = msgInfo.formatIntent === "enum" ? (msgInfo.variantKeys[selectedVariant] || msgInfo.defaultKey) : msgInfo.resourceKey;
  const message = bundle.getMessage(targetKey);
  if (!message || !message.value) throw new Error(`Message not found: ${targetKey}`);

  const formatErrors = [];
  const output = bundle.formatPattern(message.value, fArgs, formatErrors);
  if (formatErrors.length > 0) throw new Error(`Format error: ${formatErrors.join(", ")}`);
  return output;
}
