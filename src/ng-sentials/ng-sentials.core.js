(function () {
    'use strict';

    var moduleId = 'sentials.core';
    var module = angular.module(moduleId, ['ng', 'ngRoute', 'ngCookies', 'localization', 'ui.bootstrap']);



    module.provider('sentialsApp', function () {
        this.config = {
            appTitleResourceKey: "_AppTitle_",
            genericWebServiceCommunicationErrorResourceKey: "_WebServiceError_",
            codeResourceKeyFormat: "_{0}_",
            shouldShowDebugMessages: false,
            shouldUseHtml5ModeForRoutes: true,
            routes: [],
            externalLinks: [],
            webService: {},
            appErrorPrefix: '[App Error] ',
            spinner: {},
            imagesBasePath: '/Content/images/',
            unknownUserImageSource: '',
            viewHeaderTemplateUrl: '/app/infrastructure/layout/viewHeader.html'
        };

        this.events = {
            controllerActivating: 'controller.activating',
            controllerActivated: 'controller.activated',
            spinnerVisibilityChangeRequested: 'spinner.visibilityChangeRequested',
            sessionStarted: 'session.started',
            sessionEnded: 'session.ended',
        };

        this.configureLogging = function ($logProvider, sentialsAppProvider) {
            // turn debugging off/on (no info or warn)
            if ($logProvider.debugEnabled) {
                $logProvider.debugEnabled(sentialsAppProvider.config.shouldShowDebugMessages);
            }
        }

        this.configureExceptionHandling = function ($delegate, sentialsApp, sentialsLogger) {
            var appErrorPrefix = sentialsApp.config.appErrorPrefix;
            return function (exception, cause) {
                $delegate(exception, cause);
                if (appErrorPrefix && exception.message.indexOf(appErrorPrefix) === 0)
                    return;
                var errorData = { exception: exception, cause: cause };
                var msg = appErrorPrefix + exception.message;
                sentialsLogger.error(msg, errorData, moduleId);
            };
        }

        function registerRoute($routeProvider, route) {
            if (route.url)
                $routeProvider.when(route.url, route.config);

            if (route.config.nav && route.config.nav.sub)
                route.config.nav.sub.forEach(function (s) {
                    registerRoute($routeProvider, s);
                });
        }

        this.configureRouting = function ($locationProvider, $routeProvider, sentialsAppProvider) {
            $locationProvider.html5Mode(sentialsAppProvider.config.shouldUseHtml5ModeForRoutes);

            sentialsAppProvider.config.routes.forEach(function (r) {
                registerRoute($routeProvider, r);
            });

            var defaultUrl = '/';
            var defaultRoutes = sentialsAppProvider.config.routes.filter(function (r) { return r.config && r.config.isDefault; });
            if (defaultRoutes.length > 0)
                defaultUrl = defaultRoutes[0].url;

            $routeProvider.otherwise({ redirectTo: defaultUrl });
        }


        this.$get = function () {
            return {
                config: this.config,
                events: this.events,
                configureLogging: this.configureLogging,
                configureExceptionHandling: this.configureExceptionHandling,
                configureRouting: this.configureRouting
            };
        };
    });



    module.factory('sentialsLogger', ['$log', 'sentialsApp', sentialsLogger]);

    function sentialsLogger($log, sentialsApp, sentialsToaster) {
        var config = sentialsApp.config;

        var service = {
            getLogFn: getLogFn,
            message: message,
            error: error,
            success: success,
            warning: warning
        };

        return service;


        function getLogFn(moduleId, fnName) {
            fnName = fnName || 'message';
            switch (fnName.toLowerCase()) { // convert aliases
                case 'message':
                case 'info':
                case 'information':
                case 'notify':
                case 'notification':
                default:
                    fnName = 'message'; break;
                case 'success':
                    fnName = 'success'; break;
                case 'error':
                    fnName = 'error'; break;
                case 'warn':
                case 'warning':
                    fnName = 'warning'; break;
            }

            var logFn = service[fnName] || service.log;
            return function (msg, data, showToast) {
                logFn(msg, data, moduleId, (showToast === undefined) ? (config ? config.shouldShowDebugMessages : true) : showToast);
            };
        }

        function message(message, data, source, showToast) {
            log(message, data, source, showToast, 'info');
        }

        function warning(message, data, source, showToast) {
            log(message, data, source, showToast, 'warning');
        }

        function success(message, data, source, showToast) {
            log(message, data, source, showToast, 'success');
        }

        function error(message, data, source, showToast) {
            log(message, data, source, showToast, 'error');
        }

        function log(message, data, source, showToast, toastType) {
            var write = (toastType === 'error') ? $log.error : $log.log;
            source = source ? '[' + source + '] ' : '';
            if (data)
                write(source, message, data);
            else
                write(source, message);

            if (typeof showToast == 'undefined')
                showToast = config.shouldShowDebugMessages;

            if (showToast) {
                if (toastType === 'error') {
                    toastr.error(message);
                } else if (toastType === 'warning') {
                    toastr.warning(message);
                } else if (toastType === 'success') {
                    toastr.success(message);
                } else {
                    toastr.info(message);
                }
            }
        }
    }



    module.factory('sentialsUtil', ['sentialsApp', sentialsUtil]);

    function sentialsUtil(sentialsApp) {
        var config = sentialsApp.config;
        var events = sentialsApp.events;

        var throttles = {};

        var service = {
            createSearchThrottle: createSearchThrottle,
            debouncedThrottle: debouncedThrottle,
            isNumber: isNumber,
            textContains: textContains,
            format: format
        };

        return service;


        function createSearchThrottle(viewmodel, list, filteredList, filter, delay) {
            // After a delay, search a viewmodel's list using 
            // a filter function, and return a filteredList.

            // custom delay or use default
            delay = +delay || 300;
            // if only vm and list parameters were passed, set others by naming convention 
            if (!filteredList) {
                // assuming list is named sessions, filteredList is filteredSessions
                filteredList = 'filtered' + list[0].toUpperCase() + list.substr(1).toLowerCase(); // string
                // filter function is named sessionFilter
                filter = list + 'Filter'; // function in string form
            }

            // create the filtering function we will call from here
            var filterFn = function () {
                // translates to ...
                // vm.filteredSessions 
                //      = vm.sessions.filter(function(item( { returns vm.sessionFilter (item) } );
                viewmodel[filteredList] = viewmodel[list].filter(function (item) {
                    return viewmodel[filter](item);
                });
            };

            return (function () {
                // Wrapped in outer IFFE so we can use closure 
                // over filterInputTimeout which references the timeout
                var filterInputTimeout;

                // return what becomes the 'applyFilter' function in the controller
                return function (searchNow) {
                    if (filterInputTimeout) {
                        $timeout.cancel(filterInputTimeout);
                        filterInputTimeout = null;
                    }
                    if (searchNow || !delay) {
                        filterFn();
                    } else {
                        filterInputTimeout = $timeout(filterFn, delay);
                    }
                };
            })();
        }

        function debouncedThrottle(key, callback, delay, immediate) {
            // Perform some action (callback) after a delay. 
            // Track the callback by key, so if the same callback 
            // is issued again, restart the delay.

            var defaultDelay = 1000;
            delay = delay || defaultDelay;
            if (throttles[key]) {
                $timeout.cancel(throttles[key]);
                throttles[key] = undefined;
            }
            if (immediate) {
                callback();
            } else {
                throttles[key] = $timeout(callback, delay);
            }
        }

        function isNumber(val) {
            // negative or positive
            return /^[-]?\d+$/.test(val);
        }

        function textContains(text, searchText) {
            return text && -1 !== text.toLowerCase().indexOf(searchText.toLowerCase());
        }

        function format(input) {
            var args = arguments;
            return input.replace(/\{(\d+)\}/g, function (match, capture) {
                return args[1 * capture + 1];
            });
        }
    }



    module.factory('sentialsResources', ['sentialsApp', 'localize', 'sentialsUtil', sentialsResources]);

    function sentialsResources(sentialsApp, localize, sentialsUtil) {
        var config = sentialsApp.config;
        var util = sentialsUtil;

        var service = {
            get: get,
            getParsed: getParsed,
            getForCode: getForCode
        };

        return service;


        function get(resourceKey) {
            return localize.getLocalizedString(resourceKey);
        }

        function getParsed(resourceKey) {
            return localize.getLocalizedParsedString(resourceKey);
        }

        function getForCode(code) {
            return resources.get(util.format(config.codeResourceKeyFormat, code));
        }
    }



    module.factory('sentialsToaster', ['sentialsApp', 'sentialsResources', sentialsToaster]);

    function sentialsToaster(sentialsApp, sentialsResources) {
        var config = sentialsApp.config;
        var resources = sentialsResources;

        var service = {
            error: error,
            warning: warning,
            success: success,
            info: info
        };

        return service;

        function error(messageResourceKey) { toastr.error(resources.get(messageResourceKey)); }
        function warning(messageResourceKey) { toastr.warning(resources.get(messageResourceKey)); }
        function success(messageResourceKey) { toastr.success(resources.get(messageResourceKey)); }
        function info(messageResourceKey) { toastr.info(resources.get(messageResourceKey)); }
    }



    module.factory('sentialsControllers', ['$rootScope', '$q', 'sentialsApp', 'sentialsSpinner', 'sentialsLogger', sentialsControllers]);

    function sentialsControllers($rootScope, $q, sentialsApp, sentialsSpinner, sentialsLogger) {
        var config = sentialsApp.config;
        var events = sentialsApp.events;
        var spinner = sentialsSpinner;
        var log = sentialsLogger;

        var service = {
            activate: activate
        };

        initialize();

        return service;


        function initialize() {
            $rootScope.$on(events.controllerActivating,
                function (e, data) {
                    log.message('Activating: ' + data.controllerId);
                    spinner.show();
                }
            );

            $rootScope.$on(events.controllerActivated,
                function (e, data) {
                    spinner.hide();
                    log.message('Activated: ' + data.controllerId);
                }
            );
        }

        function activate(controllerId, promises) {
            promises = promises || [];
            $rootScope.$broadcast(events.controllerActivating, { controllerId: controllerId });
            return $q.all(promises).then(function (eventArgs) {
                $rootScope.$broadcast(events.controllerActivated, { controllerId: controllerId });
            });
        }
    }



    module.factory('sentialsNavigation', ['$rootScope', '$location', '$anchorScroll', '$route', '$routeParams', 'sentialsApp', 'sentialsResources', 'sentialsSpinner', 'sentialsSecurity', sentialsNavigation]);

    function sentialsNavigation($rootScope, $location, $anchorScroll, $route, $routeParams, sentialsApp, sentialsResources, sentialsSpinner, sentialsSecurity) {
        var config = sentialsApp.config;
        var routes = config.routes;
        var externalLinks = config.externalLinks;
        var resources = sentialsResources;
        var spinner = sentialsSpinner;
        var security = sentialsSecurity;

        var service = {
            refreshAppTitle: refreshAppTitle,
            getNavViewModel: getNavViewModel,
            getExternalNavViewModel: getExternalNavViewModel,
            getRegisterRouteUrl: getRegisterRouteUrl,
            toDefault: navigateToDefault,
            to: navigateTo
        };

        initialize();

        return service;


        function navigateTo(routeTitle) {
            if (routeTitle) {
                var routeTitleLowerCase = routeTitle.toLowerCase();
                var matchingRoutes = routes.filter(function (r) { return r.config && r.config.title && (r.config.title.toLowerCase() === routeTitleLowerCase); });
                if (matchingRoutes.length > 0)
                    $location.path(matchingRoutes[0].url);
            }
        }

        function navigateToDefault() {
            $location.path(getDefaultRouteUrl());
        }


        function getDefaultRouteUrl() {
            var defaultRoutes = routes.filter(function (r) { return r.config && r.config.isDefault; });
            return (defaultRoutes.length > 0) ? defaultRoutes[0].url : '/';
        }


        function getLoginRouteUrl() {
            var loginRoutes = routes.filter(function (r) { return r.config && r.config.isLogin; });
            return (loginRoutes.length > 0) ? loginRoutes[0].url : getDefaultRouteUrl();
        }


        function getNotAuthorizedRouteUrl() {
            var notAuthorizedRoutes = routes.filter(function (r) { return r.config && r.config.isNotAuthorized; });
            return (notAuthorizedRoutes.length > 0) ? notAuthorizedRoutes[0].url : getDefaultRouteUrl();
        }


        function getRegisterRouteUrl() {
            var registerRoutes = routes.filter(function (r) { return r.config && r.config.isRegister; });
            return (registerRoutes.length > 0) ? registerRoutes[0].url : getDefaultRouteUrl();
        }
        

        function initialize() {
            $rootScope.routeChangeOccurredFromRemovingShowQueryParameter = false;

            $rootScope.$on('$routeChangeStart',
                function (event, next, current) {

                    spinner.show();

                    if (next && next.$$route && next.$$route.config) {
                        if (!next.$$route.config.allowAnonymous) {
                            if (security.sessionExists()) {
                                if (!security.getPrincipal().canAccessRoute(next.$$route.url)) {
                                    event.preventDefault();
                                    $location.path(getNotAuthorizedRouteUrl());
                                }
                            }
                            else {
                                event.preventDefault();
                                $location.path(getLoginRouteUrl());
                            }
                        }
                    }
                }
            );

            $rootScope.$on('$routeChangeSuccess',
                function (event, next, current) {
                    refreshAppTitle();
                    showDelegateViewIfNeeded();
                }
            );
        }


        function refreshAppTitle() {
            var title = resources.get(config.appTitleResourceKey);

            if (canBeUsedToSearchNavRoutes($route.current)) {
                var navRouteConfig = tryGetNavConfigForRoute($route.current);
                if (navRouteConfig)
                    title = resources.get(navRouteConfig.nav.titleResourceKey) + ' | ' + title;
            }

            $rootScope.title = title;
        }


        function showDelegateViewIfNeeded() {
            if ($rootScope.routeChangeOccurredFromRemovingShowQueryParameter)
                $rootScope.routeChangeOccurredFromRemovingShowQueryParameter = false;
            else {  
                if ($routeParams.show) {
                    if ($routeParams.show != 'true')
                        $location.hash($routeParams.show);
                    $anchorScroll();
                    $rootScope.routeChangeOccurredFromRemovingShowQueryParameter = true;
                    $location.search('show', null);
                }
            }
        }


        function isNavRoute(route) {
            return route && route.config && route.config.nav;
        }


        function isExternalNavRoute(route) {
            return route && route.config && route.config.nav;
        }


        function canBeUsedToSearchNavRoutes(route) {
            return route && route.title;
        }


        function getOrderedNavRoutes() {
            return routes
                .filter(function (r) { return r.config.nav && r.config.nav.order; })
                .sort(function (r1, r2) { return r1.config.nav.order - r2.config.nav.order; });
        }


        function getOrderedExternalNavRoutes() {
            return externalLinks
                .filter(function (r) { return r.config.nav && r.config.nav.order; })
                .sort(function (r1, r2) { return r1.config.nav.order - r2.config.nav.order; });
        }


        function getLastNavRouteTitle() {
            var navRoutes = getOrderedNavRoutes();
            return (navRoutes && (navRoutes.length > 0)) ? navRoutes[navRoutes.length - 1].config.title : null;
        }


        function getLastExternalNavRouteTitle() {
            var navRoutes = getOrderedExternalNavRoutes();
            return (navRoutes && (navRoutes.length > 0)) ? navRoutes[navRoutes.length - 1].config.title : null;
        }


        function getSelfExternalNavRouteUrl() {
            var url = null;
            var navRoutes = getOrderedExternalNavRoutes();
            var selfRoutes = navRoutes.filter(function (r) { return r.config.title === 'self'; })
            if (selfRoutes && (selfRoutes.length > 0))
                url = selfRoutes[0].url;
            return url;
        }


        function tryGetNavConfigForRoute(route) {
            var routeTitle = route.title;
            var filteredRoutes = routes.filter(function (r) { return routeTitle.substr(0, r.config.title.length) === r.config.title; });
            return ((filteredRoutes.length > 0) && isNavRoute(filteredRoutes[0])) ? filteredRoutes[0].config : null;
        }

        function isCurrentRoute(route) {
            var isOrNot = false;
            if (isNavRoute(route) && canBeUsedToSearchNavRoutes($route.current)) {
                var navRouteConfig = tryGetNavConfigForRoute($route.current);
                if (navRouteConfig)
                    isOrNot = navRouteConfig.title === route.config.title;
            }
            return isOrNot;
        }


        function isLastNavRoute(route) {
            var isOrNot = false;
            if (isNavRoute(route)) {
                var lastNavRouteTitle = getLastNavRouteTitle();
                isOrNot = (route.config.title === lastNavRouteTitle);
            }
            return isOrNot;
        }


        function isLastExternalNavRoute(route) {
            var isOrNot = false;
            if (isExternalNavRoute(route)) {
                var lastNavRouteTitle = getLastExternalNavRouteTitle();
                isOrNot = (route.config.title === lastNavRouteTitle);
            }
            return isOrNot;
        }


        function isMenu(route) {
            var isOrNot = false;
            if (isNavRoute(route) && (route.config.nav.sub))
                isOrNot = true
            return isOrNot;
        }


        function isAction(route) {
            var isOrNot = false;
            if (isNavRoute(route) && (route.config.nav.action))
                isOrNot = true
            return isOrNot;
        }


        function isSelfExternalNavRoute(route) {
            var isOrNot = false;
            if (isExternalNavRoute(route)) {
                var selfUrl = getSelfExternalNavRouteUrl();
                isOrNot = (selfUrl === route.url);
            }
            return isOrNot;
        }


        function requiresSession(route) {
            var isOrNot = false;
            if (route.config && !route.config.allowAnonymous)
                isOrNot = true
            return isOrNot;
        }


        function getNavViewModelFor(route) {
            var routes = isMenu(route) ? route.config.nav.sub : [];
            routes = routes.sort(function (r1, r2) { return r1.config.nav.order - r2.config.nav.order; });
            var vm = {
                routes: routes
            };
            return vm;
        }


        function getNavViewModel() {
            var navRoutes = getOrderedNavRoutes();
            var vm = {
                routes: navRoutes,
                isCurrentRoute: isCurrentRoute,
                isLastNavRoute: isLastNavRoute,
                isMenu: isMenu,
                isAction: isAction,
                requiresSession: requiresSession,
                getNavViewModelFor: getNavViewModelFor
            };
            return vm;
        }


        function getExternalNavViewModel() {
            var navRoutes = getOrderedExternalNavRoutes();
            var vm = {
                routes: navRoutes,
                isLastNavRoute: isLastExternalNavRoute,
                isSelfNavRoute: isSelfExternalNavRoute
            };
            return vm;
        }
    }



    var ModalInstance = ['$scope', '$modalInstance', 'sentialsResources', 'options',
        function ($scope, $modalInstance, sentialsResources, options) {
            $scope.title = options.title || '';
            $scope.message = options.message || '';
            $scope.okText = options.okText || sentialsResources.get('_OkActionText_');
            $scope.cancelText = options.cancelText || sentialsResources.get('_CancelActionText_');
            $scope.ok = function () { $modalInstance.close('ok'); };
            $scope.cancel = function () { $modalInstance.dismiss('cancel'); };
        }];

    module.factory('sentialsDialog', ['$modal', '$templateCache', 'sentialsResources', 'sentialsUtil', sentialsDialog]);

    function sentialsDialog($modal, $templateCache, sentialsResources, sentialsUtil) {
        var resources = sentialsResources;
        var util = sentialsUtil;

        var service = {
            notify: notify,
            confirmRemoval: confirmRemoval,
            confirm: confirm
        };

        $templateCache.put('modalDialog.tpl.html',
            '<div>' +
            '    <div class="modal-header">' +
            '        <button type="button" class="close" data-dismiss="modal" aria-hidden="true" data-ng-click="cancel()">&times;</button>' +
            '        <h3>{{title}}</h3>' +
            '    </div>' +
            '    <div class="modal-body">' +
            '        <p>{{message}}</p>' +
            '    </div>' +
            '    <div class="modal-footer">' +
            '        <button class="btn btn-primary" data-ng-click="ok()">{{okText}}</button>' +
            '        <button class="btn btn-info" data-ng-show="cancelText" data-ng-click="cancel()">{{cancelText}}</button>' +
            '    </div>' +
            '</div>');

        return service;


        function show(title, msg, confirmText, cancelText) {
            var confirmText = confirmText || resources.get('_OkActionText_');

            var modalOptions = {
                templateUrl: 'modalDialog.tpl.html',
                controller: ModalInstance,
                keyboard: true,
                resolve: {
                    options: function () {
                        return {
                            title: title,
                            message: msg,
                            okText: confirmText,
                            cancelText: cancelText
                        };
                    }
                }
            };

            return $modal.open(modalOptions).result;
        }

        function notify(title, msg) {
            return show(title, msg)
        }

        function confirm(title, msg, confirmText) {
            return show(title, msg, confirmText, cancelText, resources.get('_CancelActionText_'));
        }

        function confirmRemoval(itemTypeResourceKey, itemName) {
            itemType = resources.get(itemTypeResourceKey || '_DefaultItemType_');
            itemName = itemName || resources.get('_DefaultItemName_');
            var title = util.format(resources.get('_ConfirmRemovalTitleFormat_'), itemType);
            var msg = util.format(resources.get('_ConfirmRemovalMessageFormat_'), itemName);
            var confirmText = resources.get('_RemoveActionText_');
            return confirm(title, msg, confirmText);
        }
    }



    module.factory('sentialsSpinner', ['$rootScope', 'sentialsApp', sentialsSpinner]);

    function sentialsSpinner($rootScope, sentialsApp) {
        var events = sentialsApp.events;

        var service = {
            hide: hide,
            show: show
        };

        return service;


        function hide() { setVisibility(false); }

        function show() { setVisibility(true); }

        function setVisibility(isVisible) {
            $rootScope.$broadcast(events.spinnerVisibilityChangeRequested, { isVisible: isVisible });
        }
    }



    module.factory('sentialsSessionManager', ['$rootScope', 'sentialsApp', 'sentialsLogger', sentialsSessionManager]);

    function sentialsSessionManager($rootScope, sentialsApp, sentialsLogger) {
        var config = sentialsApp.config;
        var events = sentialsApp.events;
        var log = sentialsLogger;

        var currentSession = null;


        var service = {
            exists: exists,
            getCurrent: getCurrent,
            begin: begin,
            end: end
        };

        return service;


        function newSessionFor(principal) {
            return {
                startMomentUtc: moment.utc(),
                principal: principal,
                getDurationMoment: function() {
                    return moment.utc().diff(this.startMomentUtc);
                }
            }
        }

        function cloned(session) {
            var copy = newSessionFor(session.principal);
            copy.startMomentUtc = session.startMomentUtc;
            return copy;
        }

        function newSessionStartedEventArgsFrom(session) {
            return cloned(session);
        }

        function newSessionEndedEventArgsFrom(session, reason) {
            return {
                durationMoment: session.getDurationMoment(),
                identity: session.principal.identity,
                reason: reason
            };
        }

        function begin(principal) {
            var sessionStarted = null;
            if (principal && !exists()) {
                var session = newSessionFor(principal);
                currentSession = session;
                var sessionStarted = newSessionStartedEventArgsFrom(session);
                log.message("Session started", sessionStarted);
                $rootScope.$broadcast(events.sessionStarted, sessionStarted);
            }
            return sessionStarted;
        }

        function end(reason) {
            var sessionEnded = null;
            if (exists()) {
                var session = currentSession;
                currentSession = null;
                sessionEnded = newSessionEndedEventArgsFrom(session, reason);
                log.message("Session ended", sessionEnded);
                $rootScope.$broadcast(events.sessionEnded, sessionEnded);
            }
            return sessionEnded;
        }

        function getCurrent() {
            return currentSession ? cloned(currentSession) : null;
        }

        function exists() {
            return currentSession ? true : false;
        }
    }



    module.factory('sentialsPrincipalFactory', ['sentialsApp', sentialsPrincipalFactory]);

    function sentialsPrincipalFactory(sentialsApp) {
        var config = sentialsApp.config;
        var events = sentialsApp.events;

        var service = {
            create: newPrincipal
        };

        return service;


        function newPrincipal(identity, roles, permissions, routes) {
            if (!roles)
                roles = [];
            if (!permissions)
                permissions = [];

            return !identity
                ? null
                : {
                    identity: identity,
                    roles: roles,
                    permissions: permissions,
                    routes: routes,
                    isInRole: function(role) {
                        var lowerCaseRole = (role) ? role.toLowerCase() : null;
                        return (lowerCaseRole) && roles.some(function (r) { r.toLowerCase() === lowerCaseRole; });
                    },
                    hasPermission: function(permission) {
                        var lowerCasePermission = (permission) ? permission.toLowerCase() : null;
                        return (lowerCasePermission) && permissions.some(function (p) { p.toLowerCase() === lowerCasePermission; });
                    },
                    canAccessRoute: function (route) {
                        var lowerCaseRoute = (route) ? route.toLowerCase() : null;
                        return (lowerCaseRoute) && routes.some(function (r) { r.toLowerCase() === lowerCaseRoute; });
                    }
                };
        }
    }



    module.factory('sentialsSecurity', ['$rootScope', 'sentialsApp', 'sentialsSessionManager', 'sentialsPrincipalFactory', sentialsSecurity]);

    function sentialsSecurity($rootScope, sentialsApp, sentialsSessionManager, sentialsPrincipalFactory) {
        var config = sentialsApp.config;
        var events = sentialsApp.events;
        var session = sentialsSessionManager;
        var principals = sentialsPrincipalFactory;

        var service = {
            getPrincipal: getPrincipal,
            principalFrom: principalFrom,
            beginSessionFor: beginSessionFor,
            endSession: endSession,
            sessionExists: sessionExists
        };

        return service;


        function getPrincipal() {
            return sessionExists() ? session.getCurrent().principal : null;
        }

        function principalFrom(identity, roles, permissions, routes) {
            return principals.create(identity, roles, permissions, routes);
        }

        function beginSessionFor(principal) {
            return session.begin(principal);
        }

        function endSession(reason) {
            return session.end(reason);
        }

        function sessionExists() {
            return session.exists();
        }
    }



    module.factory('sentialsHttp', ['$http', '$q', 'sentialsApp', 'sentialsLogger', 'sentialsResources', sentialsHttp]);

    function sentialsHttp($http, $q, sentialsApp, sentialsLogger, sentialsResources) {
        var config = sentialsApp.config;
        var log = sentialsLogger;
        var resources = sentialsResources;

        var service = {
            invoke: http
        }

        return service;


        function logError(e) {
            var message = e && e.message ? e.message : resources.get(config.genericWebServiceCommunicationErrorResourceKey);
            
            if (e && e.code) {
                var msg = resources.getForCode(e.code);
                if (msg)
                    message = msg;
            }

            log.error(message, e && e.code ? e.code : null);
            return message;
        }


        function getErrorFrom(data, status) {
            // extension point
            return data ? data : null;
        }


        function handleError(deferred, data, status, headers, httpConfig) {
            var reason = resources.get(config.genericWebServiceCommunicationErrorResourceKey);

            if (data && data.errors)
                data.errors.forEach(function(e, i) { 
                    var msg = logError(e);
                    if (i == 0)
                        reason = msg;
                });
            else
                reason = logError(getErrorFrom(data, status));

            deferred.reject(reason);
        }


        function onSuccess(response, deferred) {
            var data = response.data;
            var status = response.status;
            var headers = response.headers;
            var httpConfig = response.config;

            if (data.failed)
                handleError(deferred, data, status, headers, httpConfig);
            else
                deferred.resolve(data);
        }


        function onError(response, deferred) {
            handleError(deferred, response.data, response.status, response.headers, response.config);
        }


        function onNotify(progress, deferred) {
            deferred.notify(progress);
        }



        function http(config) {
            var deferred = $q.defer();
            $http(config).then(
                function (response) { onSuccess(response, deferred); },
                function (response) { onError(response, deferred); },
                function (response) { onNotify(response, deferred); });
            return deferred.promise;
        }
    }



    module.factory('sentials', ['$rootScope', '$q', '$timeout', '$cookies', '$cookieStore', 'sentialsApp', 'sentialsResources', 'sentialsUtil', 'sentialsLogger', 'sentialsNavigation', 'sentialsDialog', 'sentialsSpinner', 'sentialsControllers', 'sentialsSecurity', 'sentialsHttp', 'sentialsToaster', sentials]);

    function sentials($rootScope, $q, $timeout, $cookies, $cookieStore, sentialsApp, sentialsResources, sentialsUtil, sentialsLogger, sentialsNavigation, sentialsDialog, sentialsSpinner, sentialsControllers, sentialsSecurity, sentialsHttp, sentialsToaster) {

        var service = {
            $broadcast: $broadcast,
            $on: $on,
            $q: $q,
            $timeout: $timeout,
            $cookies: $cookies,
            $cookieStore: $cookieStore,
            config: sentialsApp.config,
            events: sentialsApp.events,
            resources: sentialsResources,
            util: sentialsUtil,
            log: sentialsLogger,
            nav: sentialsNavigation,
            dialog: sentialsDialog,
            spinner: sentialsSpinner,
            controllers: sentialsControllers,
            security: sentialsSecurity,
            http: sentialsHttp,
            toast: sentialsToaster
        };

        return service;


        function $broadcast() {
            return $rootScope.$broadcast.apply($rootScope, arguments);
        }

        function $on() {
            return $rootScope.$on.apply($rootScope, arguments);
        }
    }



    module.filter('resource', ['sentialsResources', function (sentialsResources) {
        return function () {
            return sentialsResources.get.apply(sentialsResources, arguments);
        };
    }]);



    module.filter('resourceParsed', ['sentialsResources', function (sentialsResources) {
        return function () {
            return sentialsResources.getParsed.apply(sentialsResources, arguments);
        };
    }]);



    module.filter('pluralized', ['$locale', function ($locale) {
        return function () {
            var count = this.args[1];
            var variants = arguments[1];
            return variants[$locale.pluralCat(count) || 'other'];
        };
    }]);



    module.filter("format", ['sentialsUtil', function (sentialsUtil) {
        return function () {
            return sentialsUtil.format.apply(sentialsUtil, arguments);
        };
    }]);



    module.directive('resource', ['sentialsResources', function (sentialsResources) {
        var directive = {
            restrict: "EAC",
            updateText: function (elm, token) {
                var values = token.split('|');
                if (values.length >= 1) {
                    // construct the tag to insert into the element
                    var tag = sentialsResources.get(values[0]);
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

            link: function (scope, elm, attrs) {
                scope.$on('localizeResourcesUpdates', function () {
                    directive.updateText(elm, attrs.resource);
                });

                attrs.$observe('resource', function () {
                    directive.updateText(elm, attrs.resource);
                });
            }
        };

        return directive;
    }]);



    module.directive('valueMatch', [function () {
        return {
            restrict: 'A',
            scope: true,
            require: 'ngModel',
            link: function (scope, elem, attrs, control) {
                var checker = function () {

                    //get the value of the first element
                    var e1 = scope.$eval(attrs.ngModel);

                    //get the value of the other element
                    var e2 = scope.$eval(attrs.valueMatch);
                    return e1 == e2;
                };
                scope.$watch(checker, function (n) {

                    //set the form control to valid if both 
                    //elements are the same, else invalid
                    control.$setValidity("unique", n);
                });
            }
        };
    }]);



    module.directive('ccSpinner', ['$window', function ($window) {
        // Description:
        //  Creates a new Spinner and sets its options
        // Usage:
        //  <div data-cc-spinner="vm.spinnerOptions"></div>
        var directive = {
            link: link,
            restrict: 'A'
        };
        return directive;

        function link(scope, element, attrs) {
            scope.spinner = null;
            scope.$watch(attrs.ccSpinner, function (options) {
                if (scope.spinner) {
                    scope.spinner.stop();
                }
                scope.spinner = new $window.Spinner(options);
                scope.spinner.spin(element[0]);
            }, true);
        }
    }]);



    module.directive('ccViewClose', function () {
        // Usage:
        // <a data-cc-view-close></a>
        // Creates:
        // <a data-cc-view-close="" href="#" class="wclose">
        //     <i class="fa fa-remove"></i>
        // </a>
        var directive = {
            link: link,
            template: '<i class="fa fa-remove"></i>',
            restrict: 'A'
        };
        return directive;

        function link(scope, element, attrs) {
            attrs.$set('href', '#');
            attrs.$set('wclose');
            element.click(close);

            function close(e) {
                e.preventDefault();
                element.parent().parent().parent().hide(100);
            }
        }
    });



    module.directive('ccViewMinimize', function () {
        // Usage:
        // <a data-cc-view-minimize></a>
        // Creates:
        // <a data-cc-view-minimize="" href="#"><i class="fa fa-chevron-up"></i></a>
        var directive = {
            link: link,
            template: '<i class="fa fa-chevron-up"></i>',
            restrict: 'A'
        };
        return directive;

        function link(scope, element, attrs) {
            //$('body').on('click', '.view .wminimize', minimize);
            attrs.$set('href', '#');
            attrs.$set('wminimize');
            element.click(minimize);

            function minimize(e) {
                e.preventDefault();
                var $wcontent = element.parent().parent().next('.view-content');
                var iElement = element.children('i');
                if ($wcontent.is(':visible')) {
                    iElement.removeClass('fa fa-chevron-up');
                    iElement.addClass('fa fa-chevron-down');
                } else {
                    iElement.removeClass('fa fa-chevron-down');
                    iElement.addClass('fa fa-chevron-up');
                }
                $wcontent.toggle(500);
            }
        }
    });



    module.directive('ccViewHeader', ['sentialsApp', function (sentialsApp) {
        var config = sentialsApp.config;
        //Usage:
        //<div data-cc-view-header title="vm.map.title"></div>
        var directive = {
            link: link,
            scope: {
                'title': '@',
                'subtitle': '@',
                'rightText': '@',
                'allowCollapse': '@'
            },
            templateUrl: config.viewHeaderTemplateUrl,
            restrict: 'A'
        };
        return directive;

        function link(scope, element, attrs) {
            attrs.$set('class', 'view-head');
        }
    }]);



    module.directive('ccImgPerson', ['sentialsApp', function (sentialsApp) {
        var config = sentialsApp.config;
        //Usage:
        //<img data-cc-img-person="{{s.speaker.imageSource}}"/>
        var basePath = config.imagesBasePath;
        var unknownImage = config.unknownUserImageSource;
        var directive = {
            link: link,
            restrict: 'A'
        };
        return directive;

        function link(scope, element, attrs) {
            attrs.$observe('ccImgPerson', function (value) {
                value = basePath + (value || unknownImage);
                attrs.$set('src', value);
            });
        }
    }]);



    module.directive('ccScrollToTop', ['$window',
        // Usage:
        // <span data-cc-scroll-to-top></span>
        // Creates:
        // <span data-cc-scroll-to-top="" class="totop">
        //      <a href="#"><i class="fa fa-chevron-up"></i></a>
        // </span>
        function ($window) {
            var directive = {
                link: link,
                template: '<a href="#"><i class="fa fa-chevron-up"></i></a>',
                restrict: 'A'
            };
            return directive;

            function link(scope, element, attrs) {
                var $win = $($window);
                element.addClass('totop');
                $win.scroll(toggleIcon);

                element.find('a').click(function (e) {
                    e.preventDefault();
                    // Learning Point: $anchorScroll works, but no animation
                    //$anchorScroll();
                    $('body').animate({ scrollTop: 0 }, 500);
                });

                function toggleIcon() {
                    $win.scrollTop() > 300 ? element.slideDown() : element.slideUp();
                }
            }
        }
    ]);



    module.directive('ccDisableNavigationOnClick', function () {
        //Usage:
        //<div data-cc-disable-navigation-on-click title="vm.map.title"></div>
        var directive = {
            link: link,
            restrict: 'A'
        };
        return directive;

        function link(scope, element, attrs) {
            attrs.$set('onclick', 'return false;');
            //attrs.$set('class', attrs.$get('class') + ' inert');
        }
    });

})();