<?php

/**
 * wechat-php-sdk
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright 2016-2018 Yan TianZeng<qinuoyun@qq.com>
 * @license   http://www.opensource.org/licenses/mit-license.php MIT
 * @link      http://www.ub-7.com
 * @github    https://github.com/qinuoyun/wechat-php-sdk
 */

namespace Wechat;

use Wechat\Lib\Cache;

/**
 * 注册SDK自动加载机制
 * @author Anyon <zoujingli@qq.com>
 * @date 2016/10/26 10:21
 */
spl_autoload_register(function ($class) {
    if (0 === stripos($class, 'Wechat\\')) {
        $filename = dirname(__DIR__) . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $class) . '.php';
        file_exists($filename) && require ($filename);
    }
});

/**
 * 微信SDK加载器
 * @author Anyon <zoujingli@qq.com>
 * @date 2016-08-21 11:06
 */
class Loader {

    /**
     * 事件注册函数
     * @var array
     */
    public static $callback = array();

    /**
     * 配置参数
     * @var array
     */
    protected static $config = array();

    /**
     * 对象缓存
     * @var array
     */
    protected static $cache = array();

    /**
     * 动态注册SDK事件处理函数
     * @param string $event 事件名称（getAccessToken|getJsTicket）
     * @param string $method 处理方法（可以是普通方法或者类中的方法）
     * @param string|null $class 处理对象（可以直接使用的类实例）
     */
    public static function register($event, $method, $class = null) {
        if (!empty($class) && class_exists($class, false) && method_exists($class, $method)) {
            self::$callback[$event] = array($class, $method);
        } else {
            self::$callback[$event] = $method;
        }
    }

    /**
     * 获取微信SDK接口对象(别名函数)
     * @param string $type 接口类型(Card|Custom|Device|Extends|Media|Menu|Oauth|Pay|Receive|Script|User|Poi)
     * @param array $config SDK配置(token,appid,appsecret,encodingaeskey,mch_id,partnerkey,ssl_cer,ssl_key,qrc_img)
     * @return WechatCard|WechatCustom|WechatDevice|WechatExtends|WechatMedia|WechatMenu|WechatOauth|WechatPay|WechatPoi|WechatReceive|WechatScript|WechatService|WechatUser
     */
    public static function &get_instance($type, $config = array()) {
        return self::get($type, $config);
    }

    /**
     * 获取微信SDK接口对象
     * @param string $type 接口类型(Card|Custom|Device|Extends|Media|Menu|Oauth|Pay|Receive|Script|User|Poi)
     * @param array $config SDK配置(token,appid,appsecret,encodingaeskey,mch_id,partnerkey,ssl_cer,ssl_key,qrc_img)
     * @return WechatCard|WechatCustom|WechatDevice|WechatExtends|WechatMedia|WechatMenu|WechatOauth|WechatPay|WechatPoi|WechatReceive|WechatScript|WechatService|WechatUser
     */
    public static function &get($type, $config = array()) {
        $index = md5(strtolower($type) . md5(json_encode(self::$config)));
        if (!isset(self::$cache[$index])) {
            $basicName = 'Wechat' . ucfirst(strtolower($type));
            $className = "\\Wechat\\{$basicName}";
            // 注册类的无命名空间别名，兼容未带命名空间的老版本SDK
            !class_exists($basicName, false) && class_alias($className, $basicName);
            self::$cache[$index] = new $className(self::config($config));
        }
        return self::$cache[$index];
    }

    /**
     * 设置配置参数
     * @param array $config
     * @return array
     */
    public static function config($config = array()) {
        !empty($config) && self::$config = array_merge(self::$config, $config);
        if (!empty(self::$config['cachepath'])) {
            Cache::$cachepath = self::$config['cachepath'];
        }
        if (empty(self::$config['component_verify_ticket'])) {
            self::$config['component_verify_ticket'] = Cache::get('component_verify_ticket');
        }
        if (empty(self::$config['token']) && !empty(self::$config['component_token'])) {
            self::$config['token'] = self::$config['component_token'];
        }
        if (empty(self::$config['appsecret']) && !empty(self::$config['component_appsecret'])) {
            self::$config['appsecret'] = self::$config['component_appsecret'];
        }
        if (empty(self::$config['encodingaeskey']) && !empty(self::$config['component_encodingaeskey'])) {
            self::$config['encodingaeskey'] = self::$config['component_encodingaeskey'];
        }
        return self::$config;
    }

}
