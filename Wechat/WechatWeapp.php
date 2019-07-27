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

use Wechat\Lib\Common;
use Wechat\Lib\Tools;
use \Exception;

/**
 * 微信网页授权
 */
class WechatWeapp extends Common {

    const WEAPP_PREFIX = 'https://api.weixin.qq.com';
    const WEAPP_AUTH_URL = '/sns/jscode2session?';
    const E_PROXY_LOGIN_FAILED = 'E_PROXY_LOGIN_FAILED';
    const NETWORK_TIMEOUT = 3000;
    const WX_LOGIN_EXPIRES = 7200;
    const WX_HEADER_CODE = 'x-wx-code';
    const WX_HEADER_ENCRYPTED_DATA = 'x-wx-encrypted-data';
    const WX_HEADER_IV = 'x-wx-iv';
    const WX_HEADER_SKEY = 'x-wx-skey';

    /**
     * 用户登录
     * @param  [type] $callback 回调函数
     * @return [type]           [description]
     */
    public function login($callback1 = "", $callback2 = "") {
        try {
            $code = self::getHttpHeader(self::WX_HEADER_CODE);
            $encryptedData = self::getHttpHeader(self::WX_HEADER_ENCRYPTED_DATA);
            $iv = self::getHttpHeader(self::WX_HEADER_IV);
            if (!$code) {
                throw new Exception("请求头未包含 code，请配合客户端 SDK 登录后再进行请求");
            }
            return $this->AuthAPI($code, $encryptedData, $iv, $callback1, $callback2);
        } catch (Exception $e) {
            return [
                'loginState' => 0,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * 检查是否登录
     * @return [type] [description]
     */
    public function check($callback = "") {
        try {
            $skey = $this->getHttpHeader(self::WX_HEADER_SKEY);

            return $this->checkLogin($skey, $callback);
        } catch (Exception $e) {
            return [
                'loginState' => 0,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * 用户登录接口
     * @param {string} $code        wx.login 颁发的 code
     * @param {string} $encryptData 加密过的用户信息
     * @param {string} $iv          解密用户信息的向量
     * @return {array} { loginState, userinfo }
     */
    public function AuthAPI($code, $encryptData, $iv, $callback1, $callback2) {
        #获取数据
        $_array_values = array_values($this->getSessionKey($code));
        #判断回调接口
        # 1. 获取 session key
        if (version_compare(PHP_VERSION, '7.0.0', 'ge')) {
            list($session_key, $openid) = array_reverse($_array_values);
        } else {
            list($session_key, $openid) = $_array_values;
        }

        # 2. 生成 3rd key (skey)
        $skey = sha1($session_key . mt_rand());

        # 如果只提供了 code
        # 就用 code 解出来的 openid 去查数据库
        if ($code && !$encryptData && !$iv) {
            $userInfo = call_user_func_array($callback2, [$openid]);
            $wxUserInfo = json_decode($userInfo['user_info']);
            # 更新登录态
            call_user_func_array($callback, [$wxUserInfo, $skey, $session_key]);
            return [
                'loginState' => 1,
                'userinfo' => [
                    'userinfo' => $wxUserInfo,
                    'skey' => $skey,
                ],
            ];
        }

        /**
         * 3. 解密数据
         * 由于官方的解密方法不兼容 PHP 7.1+ 的版本
         * 这里弃用微信官方的解密方法
         * 采用推荐的 openssl_decrypt 方法（支持 >= 5.3.0 的 PHP）
         * @see http://php.net/manual/zh/function.openssl-decrypt.php
         */
        $decryptData = \openssl_decrypt(
            base64_decode($encryptData),
            'AES-128-CBC',
            base64_decode($session_key),
            OPENSSL_RAW_DATA,
            base64_decode($iv)
        );
        $userinfo = json_decode($decryptData);

        # 4. 储存到数据库中
        call_user_func_array($callback1, [$userinfo, $skey, $session_key]);

        return [
            'loginState' => 1,
            'userinfo' => compact('userinfo', 'skey'),
        ];
    }

    /**
     * 数组颠倒
     * @param  [type] $arr [description]
     * @return [type]      [description]
     */
    public function reverse($arr) {
        $left = 0;
        $right = count($arr) - 1;
        $temp = [];
        while ($left <= $right) {
            $temp[$left] = $arr[$right];
            $temp[$right] = $arr[$left];
            $left++;
            $right--;
        }
        ksort($temp);
        return $temp;
    }

    public function checkLogin($skey, $callback) {
        $userinfo = call_user_func_array($callback, $skey);
        if ($userinfo === NULL) {
            return [
                'loginState' => 1,
                'userinfo' => [],
            ];
        }

        $wxLoginExpires = self::WX_LOGIN_EXPIRES;
        $timeDifference = time() - strtotime($userinfo->last_visit_time);

        if ($timeDifference > $wxLoginExpires) {
            return [
                'loginState' => 1,
                'userinfo' => [],
            ];
        } else {
            return [
                'loginState' => 0,
                'userinfo' => json_decode($userinfo->user_info, true),
            ];
        }
    }

    /**
     * 通过 code 换取 session key
     * @param {string} $code
     */
    public function getSessionKey($code) {
        $appId = $this->appid;
        $appSecret = $this->appsecret;
        return $this->getSessionKeyDirectly($appId, $appSecret, $code);
    }

    /**
     * 直接请求微信获取 session key
     * @param {string} $secretId  腾讯云的 secretId
     * @param {string} $secretKey 腾讯云的 secretKey
     * @param {string} $code
     * @return {array} { $session_key, $openid }
     */
    private function getSessionKeyDirectly($appId, $appSecret, $code) {
        $requestParams = [
            'appid' => $appId,
            'secret' => $appSecret,
            'js_code' => $code,
            'grant_type' => 'authorization_code',
        ];

        $result = Tools::httpGet(self::WEAPP_PREFIX . self::WEAPP_AUTH_URL . http_build_query($requestParams));

        if ($result) {
            $json = json_decode($result, true);
            if (empty($json) || !empty($json['errcode'])) {
                $this->errCode = isset($json['errcode']) ? $json['errcode'] : '505';
                $this->errMsg = isset($json['errmsg']) ? $json['errmsg'] : '无法解析接口返回内容！';
                Tools::log("WechatOauth::getOauthAccessToken Fail.{$this->errMsg} [{$this->errCode}]", "ERR - {$this->appid}");
                return false;
            }
            return $json;
        }
        return false;
    }

    /**
     * 获取头部信息
     * @param  [type] $headerKey [description]
     * @return [type]            [description]
     */
    private function getHttpHeader($headerKey) {
        $headerKey = strtoupper($headerKey);
        $headerKey = str_replace('-', '_', $headerKey);
        $headerKey = 'HTTP_' . $headerKey;
        return isset($_SERVER[$headerKey]) ? $_SERVER[$headerKey] : '';
    }

}
