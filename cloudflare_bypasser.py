import time
import os
import socket
from urllib.parse import urlparse
import threading
import env

# --- SeleniumBase Import ---
from seleniumbase import Driver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

import network
from logger import setup_logger
from env import MAX_RETRY, DEFAULT_SLEEP
from config import PROXIES, CUSTOM_DNS, DOH_SERVER

logger = setup_logger(__name__)
network.init()

DRIVER = None
DISPLAY = None
LAST_USED = None
LOCKED = threading.Lock()
TENTATIVE_CURRENT_URL = None

def _reset_pyautogui_display_state():
    try:
        import pyautogui
        import Xlib.display
        pyautogui._pyautogui_x11._display = (
                    Xlib.display.Display(os.environ['DISPLAY'])
                )
    except Exception as e:
        logger.warning(f"Error resetting pyautogui display state: {e}")

def _is_bypassed(sb) -> bool:
    try:
        title = sb.get_title().lower()
        body = sb.get_text("body").lower()
        
        # Check both title and body for verification messages
        verification_texts = [
            "just a moment",
            "verify you are human",
            "verifying you are human",
            "needs to review the security of your connection before proceeding",
            "checking your browser",
            "checking connection",
            "attention required",
            "access denied",
            "needs to review the security of your connection",
            "checking the site connection security",
            "enable javascript and cookies to continue",
            "ray id",
        ]
        for text in verification_texts:
            if text in title.lower() or text in body.lower():
                return False
                
        return True
    except Exception as e:
        logger.debug(f"Error checking page title: {e}")
        return False

def _bypass(sb, max_retries: int = MAX_RETRY) -> None:
    try_count = 0

    while not _is_bypassed(sb):
        if try_count >= max_retries:
            logger.warning("Exceeded maximum retries. Bypass failed.")
            break
        logger.info(f"Bypass attempt {try_count + 1} / {max_retries}")

        try_count += 1

        wait_time = DEFAULT_SLEEP * (try_count - 1)
        logger.info(f"Waiting {wait_time}s before trying...")
        time.sleep(wait_time)

        try:
            sb.uc_gui_click_captcha()
        except Exception as e:
            time.sleep(5)
            sb.wait_for_element_visible('body')
            try:
                sb.uc_gui_click_captcha()
            except Exception as e:
                time.sleep(DEFAULT_SLEEP)
                sb.uc_gui_click_captcha()

        if _is_bypassed(sb):
            logger.info("Bypass successful.")
        else:
            logger.info("Bypass failed.")

def _get_chromium_args():
    
    arguments = [
        "-no-sandbox",
    ]

    # Add proxy settings if configured
    if PROXIES:
        proxy_url = PROXIES.get('https') or PROXIES.get('http')
        if proxy_url:
            arguments.append(f'--proxy-server={proxy_url}')

    # --- Add Custom DNS settings ---
    try:
        if len(CUSTOM_DNS) > 0:
            if DOH_SERVER:
                logger.info(f"Configuring DNS over HTTPS (DoH) with server: {DOH_SERVER}")

                # TODO: This is probably broken and a halucination,
                # but it should still default to google DOH so its fine...
                arguments.extend(['--enable-features=DnsOverHttps', '--dns-over-https-mode=secure', f'--dns-over-https-servers="{DOH_SERVER}"'])
                doh_hostname = urlparse(DOH_SERVER).hostname
                if doh_hostname:
                    try:
                        arguments.append(f'--host-resolver-rules=MAP {doh_hostname} {socket.gethostbyname(doh_hostname)}')
                    except socket.gaierror:
                        logger.warning(f"Could not resolve DoH hostname: {doh_hostname}")
            elif CUSTOM_DNS:
                resolver_rules = [f"MAP * {dns_server}" for dns_server in CUSTOM_DNS]
                if resolver_rules:
                    arguments.append(f'--host-resolver-rules={",".join(resolver_rules)}') 
    except Exception as e:
        logger.error_trace(f"Error configuring DNS settings: {e}")
    return arguments

CHROMIUM_ARGS = _get_chromium_args()

def _get(url, retry : int = MAX_RETRY):
    try:
        logger.info(f"SB_GET: {url}")
        sb = _get_driver()
        sb.uc_open_with_reconnect(url, DEFAULT_SLEEP)
        time.sleep(DEFAULT_SLEEP)
        _bypass(sb)
        return sb.page_source
    except Exception as e:
        if retry == 0:
            logger.error_trace(f"Failed to initialize browser: {e}")
            _reset_driver()
            raise e
        logger.error_trace(f"Failed to bypass Cloudflare: {e}. Will retry...")
    return _get(url, retry - 1)

def get(url, retry : int = MAX_RETRY):
    global LOCKED, TENTATIVE_CURRENT_URL, LAST_USED
    with LOCKED:
        TENTATIVE_CURRENT_URL = url
        ret = _get(url, retry)
        LAST_USED = time.time()
        return ret

def _init_driver():
    global DRIVER
    if DRIVER:
        _reset_driver()
    driver = Driver(uc=True, headless=False, chromium_arg=CHROMIUM_ARGS)
    DRIVER = driver
    time.sleep(DEFAULT_SLEEP)
    return driver

def _get_driver():
    global DRIVER, DISPLAY
    global LAST_USED
    LAST_USED = time.time()
    if env.DOCKERMODE and env.USE_CF_BYPASS and not DISPLAY:
        from pyvirtualdisplay import Display
        display = Display(visible=False, size=(800, 600))
        display.start()
        logger.info("Display started")
        DISPLAY = display
        time.sleep(DEFAULT_SLEEP)
        _reset_pyautogui_display_state()
    if not DRIVER:
        return _init_driver()
    return DRIVER

def _reset_driver():
    logger.info("Resetting driver...")
    global DRIVER, DISPLAY
    if DRIVER:
        try:
            DRIVER.quit()
            DRIVER = None
        except Exception as e:
            logger.warning(f"Error quitting driver: {e}")
        time.sleep(0.5)
    if DISPLAY:
        try:
            DISPLAY.stop()
            DISPLAY = None
        except Exception as e:
            logger.warning(f"Error stopping display: {e}")
        time.sleep(0.5)
    try:
        os.system("pkill -f Xvfb")
    except Exception as e:
        logger.warning(f"Error killing Xvfb: {e}")
    time.sleep(0.5)
    try:
        os.system("pkill -f chrom")
    except Exception as e:
        logger.warning(f"Error killing chrom: {e}")
    time.sleep(0.5)


def _cleanup_driver():
    global LOCKED
    global LAST_USED
    with LOCKED:
        if LAST_USED:
            if time.time() - LAST_USED >= env.BYPASS_RELEASE_INACTIVE_MIN * 60:
                _reset_driver()
                LAST_USED = None
                logger.info("Driver reset due to inactivity.")

def _cleanup_loop():
    while True:
        _cleanup_driver()
        time.sleep(max(env.BYPASS_RELEASE_INACTIVE_MIN / 2, 1))

def _debug_loop():
    while True:
        if DRIVER:
            try:
                # Get URL with fallback to tentative URL
                try:
                    url = DRIVER.current_url
                except Exception as e:
                    url = TENTATIVE_CURRENT_URL or "unknown_url"

                # Create timestamp and filename
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"screenshot_{timestamp}_{url}"
                
                # Sanitize filename
                sanitized_filename = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in filename)
                sanitized_filename = sanitized_filename[:100] + ".png"  # Limit length
                
                # Ensure screenshots directory exists
                screenshots_dir = env.LOG_DIR / "screenshots"
                screenshots_dir.mkdir(parents=True, exist_ok=True)
                
                # Save screenshot
                full_path = screenshots_dir / sanitized_filename

                DRIVER.save_screenshot(str(full_path))
            except Exception as e:
                pass
        time.sleep(1)

def _init_cleanup_thread():
    cleanup_thread = threading.Thread(target=_cleanup_loop)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    if env.DEBUG:
        path = env.LOG_DIR / "screenshots"
        path.mkdir(parents=True, exist_ok=True)
        debug_thread = threading.Thread(target=_debug_loop)
        debug_thread.daemon = True
        debug_thread.start()

def wait_for_result(func, timeout : int = 10, condition : any = True):
    start_time = time.time()
    while time.time() - start_time < timeout:
        result = func()
        if condition(result):
            return result
        time.sleep(0.5)
    return None
_init_cleanup_thread()
