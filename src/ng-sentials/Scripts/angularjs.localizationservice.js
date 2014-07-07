'use strict';

/*
 * An AngularJS Localization Service
 *
 * Based on code by Jim Lavin <http://codingsmackdown.tv>, modified by Petr Kadlec <mormegil@centrum.cz>
 */

angular.module('localization', []).
    provider('localize', function() {
        var localizationProvider = {};
        // URL template for resource files
        localizationProvider['resourceUrl'] = '/i18n/resources-locale_<>.js';
        // initial language
        localizationProvider['language'] = null;

        // processing of parameter placeholders (e.g. $1)
        var paramsRegexen = [];
        for (var i = 1; i < 10; ++i) {
            paramsRegexen[i] = new RegExp('\\$' + i, 'g');
        }
        function substituteParams(text, params) {
            for (var i = 1; i < params.length; ++i) {
                text = text.replace(paramsRegexen[i], params[i]);
            }
            return text;
        }

        // factory method
        localizationProvider['$get'] = ['$http', '$rootScope', '$window', '$interpolate', function ($http, $rootScope, $window, $interpolate) {

            function loadResourceFile(_localize, lang, successCallback) {
                $http({ method: "GET", url: _localize.resourceUrl.replace('<>', lang), cache: true }).success(successCallback);
            }

            var localize = {
                resourceUrl: localizationProvider.resourceUrl,
                // if language not specified explicitly, use the $window service to get the language of the user's browser as the default
                language: localizationProvider.language || $window.navigator.userLanguage || $window.navigator.language,
                // array to hold the localized resource string entries
                dictionary: [],
                defaultDictionary: [],
                // cached parsers for parsed messages (see getLocalizedParsedString)
                parsers: [],

                setLanguage: function (value) {
                    // forget the original dictionary
                    localize.dictionary = [];
                    localize.parsers = [];
                    // change language and reload
                    localize.language = value;
                    localize.loadResources();
                },

                getLocalizedString: function (messageKey) {
                    // translate using the dictionary
                    var localized = localize.dictionary[messageKey] || localize.defaultDictionary[messageKey] || '';

                    // substitute arguments, if any
                    localized = substituteParams(localized, arguments);

                    return localized;
                },

                getLocalizedParsedString: function (messageKey /* ... */) {
                    // get the translated message text from the dictionary
                    var localized = localize.dictionary[messageKey] || localize.defaultDictionary[messageKey] || '';

                    // try if we already have a parser for this message cached
                    var parser = localize.parsers[localized];
                    if (parser === undefined) {
                        // otherwise, create parser and store into the cache
                        parser = $interpolate(localized);
                        localize.parsers[localized] = parser;
                    }

                    // evaluate the message for the current arguments
                    var context = {
                        args: arguments
                    };
                    localized = parser(context);

                    // substitute arguments, if any
                    localized = substituteParams(localized, arguments);

                    return localized;
                },

                loadResources: function () {
                    // request the resource files
                    loadResourceFile(localize, localize.language, localize.resourceFileLoaded);
                },

                resourceFileLoaded: function (data) {
                    // store the returned array in the dictionary
                    localize.dictionary = data || [];
                    // broadcast that the file has been loaded
                    $rootScope.$broadcast('localizeResourcesUpdates');
                }
            };

            // load the default translation
            loadResourceFile(localize, 'default', function (data) {
                localize.defaultDictionary = data || [];
            });

            // load the translation for the default language
            localize.loadResources();

            // return the local instance when called
            return localize;
        }];

        return localizationProvider;
    }).
    filter('i18n', ['localize', function (localize) {
        return function() {
            return localize.getLocalizedString.apply(localize, arguments);
        };
    }]).
    filter('i18nparsed', ['localize', function (localize) {
        return function () {
            return localize.getLocalizedParsedString.apply(localize, arguments);
        };
    }]).
    filter('plural', ['$locale', function ($locale) {
        return function () {
            var count = this.args[1];
            var variants = arguments[1];
            return variants[$locale.pluralCat(count) || 'other'];
        };
    }]).
    directive('i18n', ['localize', function (localize) {
        var i18nDirective = {
            restrict:"EAC",
            updateText:function(elm, token){
                var values = token.split('|');
                if (values.length >= 1) {
                    // construct the tag to insert into the element
                    var tag = localize.getLocalizedString(values[0]);
                    // update the element only if data was returned
                    if ((tag !== null) && (tag !== undefined) && (tag !== '')) {
                        if (values.length > 1) {
                            for (var index = 1; index < values.length; index++) {
                                var target = '{' + (index - 1) + '}';
                                tag = tag.replace(target, values[index]);
                            }
                        }
                        // insert the text into the element
                        elm.text(tag);
                    };
                }
            },

            link:function (scope, elm, attrs) {
                scope.$on('localizeResourcesUpdates', function() {
                    i18nDirective.updateText(elm, attrs.i18n);
                });

                attrs.$observe('i18n', function () {
                    i18nDirective.updateText(elm, attrs.i18n);
                });
            }
        };

        return i18nDirective;
    }]);