var passport = require('passport-strategy')
var  util = require('util')
var  discourse_sso = require("./passport-discourse-sso.js");

var Provider = null;
var Host = null;
var RouteCallBack = null;

function Strategy(options, verify, host, routeCallBackPath) {
    Host = host;
    util.inherits(Strategy, passport.Strategy);
    RouteCallBack = routeCallBackPath;
    if (typeof verify !== 'function') throw new TypeError("passport-discourse requires a verify callback");

    if (!Provider) Provider = new discourse_sso(options);
    passport.Strategy.call(this);
    this.name = 'discourse';
    this.verify_cb = verify;
}

Strategy.prototype.authenticate = function (req, options) {
    var self = this;
    if (!options) options = {};
    function _verify_discourse_sso(req, res) {
        var ret = Provider.validateAuth(req.originalUrl);
        var profile = {};
        if (ret) {
            profile.username = ret.username;
            profile.email = ret.email;
            profile.displayName = ret.name;
        }
        self.verify_cb(null, null, profile, function () {
            if (ret) {
                self.success(profile);
            } else {
                self.fail("Failed to validate user");
            }
        });
    }

    var s = req.originalUrl.split(RouteCallBack);
    if (s.length > 1 && s[0].length == 0) {
        _verify_discourse_sso(req);
    } else {
        var m = Provider.valid_server_re.exec(req.headers.referer);
        referal_url = Host + RouteCallBack;
        var argz = arguments;
        var auth_req = Provider.generateAuthRequest(referal_url, options).then(function (ret) {
            self.redirect(ret.url_redirect);

        });
    }
}

module.exports = Strategy;