#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <stdarg.h>

static const uintptr_t kWXRevokeParserEntryVA = 0x4C34E40;
static const uintptr_t kWXRevokeParserImplVA = 0x4C34E4E;
static const uintptr_t kWXRevokeParserSlotVA = 0x9952F30;
static NSString *const kWXRuntimeLogPath = @"/tmp/wechat_anti_revoke_runtime.log";
static NSString *const kWXRuntimeBuildTag = @"rev-transform-v4";
static NSString *const kWXMessageServiceClassName = @"MessageService";
static NSString *const kWXDeleteSelectorName = @"DelMsg:msgList:isDelAll:isManual:";

static NSString *const kWXAssistantMenuTitle = @"小助手";
static NSString *const kWXAssistantNoticePending = @"聊天内撤回提示：等待 revokemsg hook";
static NSString *const kWXAssistantNoticeReady = @"聊天内撤回提示：已接管 revokemsg 入口";

typedef BOOL (*WXRevokeParserFn)(void *output, void *arg1, void *arg2);
typedef void (*WXDeleteMessageFn)(id self, SEL _cmd, id arg1, id msgList, BOOL isDelAll, BOOL isManual);

static WXRevokeParserFn gWXOriginalRevokeParser = NULL;
static WXDeleteMessageFn gWXOriginalDeleteMessage = NULL;
static volatile BOOL gWXRevokeHookInstalled = NO;
static volatile BOOL gWXDeleteHookInstalled = NO;
static volatile int gWXRevokeHookAttempts = 0;
static volatile int gWXDeleteHookAttempts = 0;
static NSMutableSet<NSString *> *gWXPendingRevokeMessageIDs = nil;

@interface WXAssistantController : NSObject

@property (nonatomic, strong) NSMenuItem *statusMenuItem;
@property (nonatomic, strong) NSMenuItem *noticeMenuItem;

+ (instancetype)sharedController;
- (void)start;
- (void)updateHookStatus:(BOOL)installed;

@end

static void WXAppendLog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static void WXAppendLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], message];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil) {
        return;
    }

    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:kWXRuntimeLogPath]) {
        [data writeToFile:kWXRuntimeLogPath atomically:YES];
        return;
    }

    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:kWXRuntimeLogPath];
    if (handle == nil) {
        [data writeToFile:kWXRuntimeLogPath atomically:YES];
        return;
    }

    @try {
        [handle seekToEndOfFile];
        [handle writeData:data];
    } @catch (__unused NSException *exception) {
    } @finally {
        [handle closeFile];
    }
}

static uintptr_t WXFindImageSlide(const char *suffix) {
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t index = 0; index < imageCount; index++) {
        const char *name = _dyld_get_image_name(index);
        if (name == NULL) {
            continue;
        }
        size_t nameLength = strlen(name);
        size_t suffixLength = strlen(suffix);
        if (nameLength < suffixLength) {
            continue;
        }
        if (strcmp(name + nameLength - suffixLength, suffix) == 0) {
            return (uintptr_t)_dyld_get_image_vmaddr_slide(index);
        }
    }
    return 0;
}

static NSString *WXReadCppString(void *address) {
    if (address == NULL) {
        return @"";
    }

    const uint8_t *bytes = (const uint8_t *)address;
    BOOL isLong = (bytes[0] & 0x1) != 0;
    if (isLong) {
        const uint64_t size = *(const uint64_t *)(bytes + 8);
        const char *ptr = *(char *const *)(bytes + 16);
        if (ptr == NULL || size == 0) {
            return @"";
        }
        return [[NSString alloc] initWithBytes:ptr
                                        length:(NSUInteger)MIN(size, (uint64_t)4096)
                                      encoding:NSUTF8StringEncoding] ?: @"";
    }

    const uint64_t size = (uint64_t)(bytes[0] >> 1);
    if (size == 0) {
        return @"";
    }
    return [[NSString alloc] initWithBytes:bytes + 1
                                    length:(NSUInteger)MIN(size, (uint64_t)22)
                                  encoding:NSUTF8StringEncoding] ?: @"";
}

static void WXClearCppString(void *address) {
    if (address == NULL) {
        return;
    }
    memset(address, 0, 24);
}

static NSString *WXHexDump(const void *bytes, size_t length) {
    if (bytes == NULL || length == 0) {
        return @"";
    }
    const uint8_t *buffer = (const uint8_t *)bytes;
    NSMutableString *result = [NSMutableString stringWithCapacity:length * 3];
    for (size_t index = 0; index < length; index++) {
        [result appendFormat:@"%02X", buffer[index]];
        if (index + 1 < length) {
            [result appendString:@" "];
        }
    }
    return result;
}

static NSString *WXPreviewCString(const void *bytes, size_t maxLength) {
    if (bytes == NULL || maxLength == 0) {
        return @"";
    }
    const uint8_t *buffer = (const uint8_t *)bytes;
    size_t length = 0;
    while (length < maxLength) {
        uint8_t value = buffer[length];
        if (value == 0) {
            break;
        }
        if (value < 0x20 && value != '\n' && value != '\r' && value != '\t') {
            break;
        }
        length += 1;
    }
    if (length == 0) {
        return @"";
    }
    return [[NSString alloc] initWithBytes:buffer length:length encoding:NSUTF8StringEncoding] ?: @"";
}

static BOOL WXCopyMemory(const void *address, void *buffer, size_t length) {
    if (address == NULL || buffer == NULL || length == 0) {
        return NO;
    }
    vm_size_t outSize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)length,
                                         (vm_address_t)buffer,
                                         &outSize);
    return kr == KERN_SUCCESS && outSize == (vm_size_t)length;
}

static NSArray<NSString *> *WXCollectPrintableStrings(const uint8_t *bytes, size_t length) {
    NSMutableArray<NSString *> *strings = [NSMutableArray array];
    size_t start = SIZE_MAX;
    for (size_t index = 0; index < length; index++) {
        uint8_t value = bytes[index];
        BOOL printable = (value >= 0x20 && value < 0x7F) || value >= 0x80;
        if (printable) {
            if (start == SIZE_MAX) {
                start = index;
            }
            continue;
        }
        if (start != SIZE_MAX && index - start >= 4) {
            NSString *text = [[NSString alloc] initWithBytes:bytes + start
                                                      length:index - start
                                                    encoding:NSUTF8StringEncoding];
            if (text.length > 0) {
                [strings addObject:text];
            }
        }
        start = SIZE_MAX;
    }
    if (start != SIZE_MAX && length - start >= 4) {
        NSString *text = [[NSString alloc] initWithBytes:bytes + start
                                                  length:length - start
                                                encoding:NSUTF8StringEncoding];
        if (text.length > 0) {
            [strings addObject:text];
        }
    }
    return strings;
}

static NSString *WXDescribeMemoryObject(const void *address, size_t probeLength) {
    if (address == NULL || probeLength == 0) {
        return @"";
    }

    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    uint8_t local[512] = {0};
    size_t length = MIN(probeLength, sizeof(local));
    if (!WXCopyMemory(address, local, length)) {
        return @"";
    }

    NSArray<NSString *> *embedded = WXCollectPrintableStrings(local, length);
    if (embedded.count > 0) {
        [parts addObject:[NSString stringWithFormat:@"embedded=%@", [embedded componentsJoinedByString:@" | "]]];
    }

    for (size_t offset = 0; offset + sizeof(uint64_t) <= MIN(length, (size_t)128); offset += 8) {
        uint64_t candidate = *(const uint64_t *)(local + offset);
        if (candidate < 0x100000000ULL) {
            continue;
        }
        uint8_t pointed[256] = {0};
        if (!WXCopyMemory((const void *)(uintptr_t)candidate, pointed, sizeof(pointed))) {
            continue;
        }
        NSArray<NSString *> *strings = WXCollectPrintableStrings(pointed, sizeof(pointed));
        if (strings.count == 0) {
            continue;
        }
        [parts addObject:[NSString stringWithFormat:@"+0x%zx->0x%llx=%@",
                          offset,
                          candidate,
                          [strings componentsJoinedByString:@" | "]]];
    }

    return [parts componentsJoinedByString:@" ; "];
}

static NSString *WXExtractPrimaryPayload(const void *address) {
    if (address == NULL) {
        return @"";
    }

    uint8_t local[64] = {0};
    if (!WXCopyMemory(address, local, sizeof(local))) {
        return @"";
    }

    for (size_t offset = 0; offset + sizeof(uint64_t) <= sizeof(local); offset += 8) {
        uint64_t candidate = *(const uint64_t *)(local + offset);
        if (candidate < 0x100000000ULL) {
            continue;
        }

        uint8_t pointed[2048] = {0};
        if (!WXCopyMemory((const void *)(uintptr_t)candidate, pointed, sizeof(pointed))) {
            continue;
        }

        NSString *text = [[NSString alloc] initWithBytes:pointed
                                                  length:strnlen((const char *)pointed, sizeof(pointed))
                                                encoding:NSUTF8StringEncoding];
        if (text.length == 0) {
            continue;
        }
        if ([text containsString:@"<sysmsg type=\"revokemsg\">"]) {
            return text;
        }
    }

    return @"";
}

static NSString *WXClassName(id object) {
    if (object == nil) {
        return @"<nil>";
    }
    return NSStringFromClass([object class]) ?: @"<unknown>";
}

static void WXScrollViewToBottom(NSScrollView *scrollView, NSUInteger *scrollCount) {
    if (scrollView == nil) {
        return;
    }

    BOOL didScroll = NO;
    if ([scrollView respondsToSelector:@selector(scrollToEndOfDocument:)]) {
        ((void (*)(id, SEL, id))objc_msgSend)(scrollView, @selector(scrollToEndOfDocument:), nil);
        didScroll = YES;
    }

    NSView *documentView = scrollView.documentView;
    NSClipView *clipView = scrollView.contentView;
    if (documentView != nil && clipView != nil) {
        NSRect documentFrame = documentView.frame;
        NSRect visibleRect = clipView.bounds;
        CGFloat maxY = NSMaxY(documentFrame) - NSHeight(visibleRect);
        if (maxY < 0) {
            maxY = 0;
        }
        NSPoint targetPoint = NSMakePoint(NSMinX(visibleRect), maxY);
        [clipView scrollToPoint:targetPoint];
        [scrollView reflectScrolledClipView:clipView];
        didScroll = YES;
    }

    if (didScroll && scrollCount != NULL) {
        *scrollCount += 1;
    }
}

static void WXInvokeVoidSelectorIfResponds(id target, SEL selector, NSUInteger *reloadCount) {
    if (target == nil || selector == NULL || ![target respondsToSelector:selector]) {
        return;
    }
    ((void (*)(id, SEL))objc_msgSend)(target, selector);
    if (reloadCount != NULL) {
        *reloadCount += 1;
    }
}

static void WXRefreshObject(id target, NSUInteger *reloadCount) {
    if (target == nil) {
        return;
    }

    WXInvokeVoidSelectorIfResponds(target, @selector(sortAndReloadDetailData), reloadCount);
    WXInvokeVoidSelectorIfResponds(target, @selector(reloadData), reloadCount);
    WXInvokeVoidSelectorIfResponds(target, @selector(refreshStatus), reloadCount);
    WXInvokeVoidSelectorIfResponds(target, @selector(redisplay), reloadCount);
}

static void WXReloadViewTree(NSView *view, NSUInteger *reloadCount) {
    if (view == nil) {
        return;
    }

    WXRefreshObject(view, reloadCount);
    if ([view isKindOfClass:[NSScrollView class]]) {
        WXScrollViewToBottom((NSScrollView *)view, NULL);
    }

    for (NSView *subview in view.subviews) {
        WXReloadViewTree(subview, reloadCount);
    }
}

static void WXRefreshViewControllerTree(NSViewController *controller, NSUInteger *reloadCount) {
    if (controller == nil) {
        return;
    }

    WXRefreshObject(controller, reloadCount);
    WXReloadViewTree(controller.view, reloadCount);

    for (NSViewController *child in controller.childViewControllers) {
        WXRefreshViewControllerTree(child, reloadCount);
    }
}

static void WXRefreshResponderChain(NSResponder *responder, NSUInteger *reloadCount) {
    NSUInteger hop = 0;
    while (responder != nil && hop < 12) {
        WXRefreshObject(responder, reloadCount);
        if ([responder isKindOfClass:[NSView class]]) {
            WXReloadViewTree((NSView *)responder, reloadCount);
        } else if ([responder isKindOfClass:[NSViewController class]]) {
            WXRefreshViewControllerTree((NSViewController *)responder, reloadCount);
        }
        responder = responder.nextResponder;
        hop += 1;
    }
}

static void WXRefreshVisibleChatViews(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSArray<NSWindow *> *windows = [NSApp windows];
        NSUInteger reloaded = 0;
        NSUInteger scrolled = 0;
        NSMutableArray<NSString *> *windowSummaries = [NSMutableArray array];

        for (NSWindow *window in windows) {
            if (!window.isVisible) {
                continue;
            }
            NSString *contentVCName = WXClassName(window.contentViewController);
            NSString *firstResponderName = WXClassName(window.firstResponder);
            [windowSummaries addObject:[NSString stringWithFormat:@"window=%@ contentVC=%@ firstResponder=%@",
                                        window.title ?: @"<untitled>",
                                        contentVCName,
                                        firstResponderName]];

            WXRefreshViewControllerTree(window.contentViewController, &reloaded);
            WXRefreshResponderChain(window.firstResponder, &reloaded);
            WXReloadViewTree(window.contentView, &reloaded);
            for (NSView *subview in window.contentView.subviews) {
                if ([subview isKindOfClass:[NSScrollView class]]) {
                    WXScrollViewToBottom((NSScrollView *)subview, &scrolled);
                }
            }
            [window.contentView layoutSubtreeIfNeeded];
            [window displayIfNeeded];
        }

        WXAppendLog(@"[ui] reloaded visible chat views count=%lu scrolled=%lu summary=%@",
                    (unsigned long)reloaded,
                    (unsigned long)scrolled,
                    [windowSummaries componentsJoinedByString:@" ; "]);
    });
}

static void WXScheduleVisibleChatRefresh(void) {
    NSArray<NSNumber *> *delays = @[@0.0, @0.08, @0.25, @0.45];
    for (NSNumber *delay in delays) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            WXRefreshVisibleChatViews();
        });
    }
}

static NSString *WXExtractXMLValue(NSString *xml, NSString *tag) {
    if (xml.length == 0 || tag.length == 0) {
        return @"";
    }
    NSString *startToken = [NSString stringWithFormat:@"<%@>", tag];
    NSString *endToken = [NSString stringWithFormat:@"</%@>", tag];
    NSRange start = [xml rangeOfString:startToken];
    if (start.location == NSNotFound) {
        return @"";
    }
    NSUInteger valueStart = NSMaxRange(start);
    NSRange searchRange = NSMakeRange(valueStart, xml.length - valueStart);
    NSRange end = [xml rangeOfString:endToken options:0 range:searchRange];
    if (end.location == NSNotFound || end.location < valueStart) {
        return @"";
    }
    NSString *value = [xml substringWithRange:NSMakeRange(valueStart, end.location - valueStart)];
    if ([value hasPrefix:@"<![CDATA["] && [value hasSuffix:@"]]>"] && value.length >= 12) {
        value = [value substringWithRange:NSMakeRange(9, value.length - 12)];
    }
    return value;
}

static void WXEnsureRevokeState(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gWXPendingRevokeMessageIDs = [[NSMutableSet alloc] init];
    });
}

static void WXRememberPendingRevokeIDs(NSString *payload) {
    WXEnsureRevokeState();
    NSArray<NSString *> *candidates = @[
        WXExtractXMLValue(payload, @"msgid"),
        WXExtractXMLValue(payload, @"newmsgid")
    ];
    @synchronized (gWXPendingRevokeMessageIDs) {
        for (NSString *candidate in candidates) {
            if (candidate.length > 0) {
                [gWXPendingRevokeMessageIDs addObject:candidate];
            }
        }
        WXAppendLog(@"[revokemsg] pending ids=%@", [[gWXPendingRevokeMessageIDs allObjects] componentsJoinedByString:@","]);
    }
}

static BOOL WXMessageListContainsPendingID(id msgList) {
    WXEnsureRevokeState();

    NSArray *items = nil;
    if ([msgList isKindOfClass:[NSArray class]]) {
        items = (NSArray *)msgList;
    } else if (msgList != nil) {
        items = @[msgList];
    }

    if (items.count == 0) {
        return NO;
    }

    NSMutableArray<NSString *> *descriptions = [NSMutableArray arrayWithCapacity:items.count];
    BOOL matched = NO;

    @synchronized (gWXPendingRevokeMessageIDs) {
        for (id item in items) {
            NSString *text = [[item description] copy] ?: @"";
            [descriptions addObject:text];
            for (NSString *pendingID in gWXPendingRevokeMessageIDs) {
                if (pendingID.length > 0 && [text containsString:pendingID]) {
                    matched = YES;
                    break;
                }
            }
            if (matched) {
                break;
            }
        }

        WXAppendLog(@"[delmsg] pending=%@ msgList=%@ matched=%@",
                    [[gWXPendingRevokeMessageIDs allObjects] componentsJoinedByString:@","],
                    [descriptions componentsJoinedByString:@" | "],
                    matched ? @"YES" : @"NO");

        if (matched) {
            [gWXPendingRevokeMessageIDs removeAllObjects];
        }
    }

    return matched;
}

static void WXDeleteMessageHook(id self, SEL _cmd, id arg1, id msgList, BOOL isDelAll, BOOL isManual) {
    if (WXMessageListContainsPendingID(msgList)) {
        WXAppendLog(@"[delmsg] skip delete arg1=%@ isDelAll=%d isManual=%d", arg1, isDelAll, isManual);
        return;
    }

    if (gWXOriginalDeleteMessage != NULL) {
        gWXOriginalDeleteMessage(self, _cmd, arg1, msgList, isDelAll, isManual);
    }
}

static BOOL WXRevokeParserHook(void *output, void *arg1, void *arg2) {
    if (gWXOriginalRevokeParser == NULL) {
        return YES;
    }

    NSString *rawPayload = WXExtractPrimaryPayload(arg1);
    BOOL isPrimaryPayload = rawPayload.length > 0 &&
        [rawPayload containsString:@"<session>"] &&
        [rawPayload containsString:@"<msgid>"] &&
        [rawPayload containsString:@"<newmsgid>"];

    BOOL shouldTransformPrimaryPayload = isPrimaryPayload && !gWXDeleteHookInstalled;

    if (isPrimaryPayload && gWXDeleteHookInstalled) {
        WXAppendLog(@"[revokemsg] allow native flow with delete interception payload=%@", rawPayload);
        WXRememberPendingRevokeIDs(rawPayload);
    } else if (shouldTransformPrimaryPayload) {
        WXAppendLog(@"[revokemsg] allow parse and transform primary payload=%@", rawPayload);
    }

    BOOL result = gWXOriginalRevokeParser(output, arg1, arg2);
    if (!result || output == NULL) {
        return result;
    }

    if (isPrimaryPayload && gWXDeleteHookInstalled) {
        return result;
    }

    uint8_t *base = (uint8_t *)output;
    NSString *type = WXReadCppString(base + 0x128);
    if (![type isEqualToString:@"revokemsg"]) {
        return result;
    }

    int32_t field140 = *(int32_t *)(base + 0x140);
    int32_t field144 = *(int32_t *)(base + 0x144);
    uint64_t field148 = *(uint64_t *)(base + 0x148);
    int32_t field208 = *(int32_t *)(base + 0x208);

    NSString *replaceMessage = WXReadCppString(base + 0x150);
    NSString *session = WXReadCppString(base + 0x168);
    NSString *field198 = WXReadCppString(base + 0x198);
    NSString *field1B0 = WXReadCppString(base + 0x1B0);
    NSString *field248 = WXReadCppString(base + 0x248);
    NSString *field260 = WXReadCppString(base + 0x260);
    NSString *field278 = WXReadCppString(base + 0x278);
    NSString *field290 = WXReadCppString(base + 0x290);
    NSString *arg1Preview = WXPreviewCString(arg1, 512);
    NSString *arg2Preview = WXPreviewCString(arg2, 512);

    WXAppendLog(@"[revokemsg] session=%@ replace=%@ field140=%d field144=%d field148=%llu field208=%d field198=%@ field1B0=%@ field248=%@ field260=%@ field278=%@ field290=%@ arg1=%p arg1Preview=%@ arg1Struct=%@ arg1Dump=%@ arg2=%p arg2Preview=%@ arg2Struct=%@ arg2Dump=%@ dump=%@",
                session,
                replaceMessage,
                field140,
                field144,
                field148,
                field208,
                field198,
                field1B0,
                field248,
                field260,
                field278,
                field290,
                arg1,
                arg1Preview,
                WXDescribeMemoryObject(arg1, 256),
                WXHexDump(arg1, 128),
                arg2,
                arg2Preview,
                WXDescribeMemoryObject(arg2, 256),
                WXHexDump(arg2, 128),
                WXHexDump(base + 0x128, 0x190));

    // Primary revoke payload carries msgid/newmsgid and triggers deletion.
    // Secondary payload carries only the display text and should be preserved
    // so WeChat can render the in-chat "撤回了一条消息" marker.
    if (shouldTransformPrimaryPayload && field140 == 0 && session.length > 0 && field148 != 0) {
        *(int32_t *)(base + 0x140) = 1;
        *(uint64_t *)(base + 0x148) = 0;
        WXAppendLog(@"[revokemsg] transformed primary revoke event to display-only session=%@ newmsgid=%llu",
                    session,
                    field148);
        WXScheduleVisibleChatRefresh();
        return YES;
    } else if (field140 == 0 && session.length > 0 && field148 != 0) {
        WXAppendLog(@"[revokemsg] fallback suppress primary revoke event for session=%@ newmsgid=%llu",
                    session,
                    field148);
        return NO;
    } else {
        WXAppendLog(@"[revokemsg] allow display payload field140=%d session=%@", field140, session);
    }
    return YES;
}

static void WXInstallDeleteRuntimeHook(void) {
    if (gWXDeleteHookInstalled) {
        return;
    }

    gWXDeleteHookAttempts += 1;
    Class messageServiceClass = objc_getClass([kWXMessageServiceClassName UTF8String]);
    if (messageServiceClass == Nil) {
        WXAppendLog(@"[delmsg] attempt=%d class %@ not found", gWXDeleteHookAttempts, kWXMessageServiceClassName);
        if (gWXDeleteHookAttempts < 20) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                WXInstallDeleteRuntimeHook();
            });
        }
        return;
    }

    SEL selector = NSSelectorFromString(kWXDeleteSelectorName);
    Method method = class_getInstanceMethod(messageServiceClass, selector);
    if (method == NULL) {
        WXAppendLog(@"[delmsg] attempt=%d selector %@ missing on %@",
                    gWXDeleteHookAttempts,
                    kWXDeleteSelectorName,
                    kWXMessageServiceClassName);
        return;
    }

    gWXOriginalDeleteMessage = (WXDeleteMessageFn)method_getImplementation(method);
    method_setImplementation(method, (IMP)WXDeleteMessageHook);
    gWXDeleteHookInstalled = YES;

    const char *types = method_getTypeEncoding(method);
    WXAppendLog(@"[delmsg] installed class=%@ selector=%@ types=%s original=%p",
                kWXMessageServiceClassName,
                kWXDeleteSelectorName,
                types != NULL ? types : "",
                gWXOriginalDeleteMessage);
}

static void WXInstallRevokeRuntimeHook(void) {
    if (gWXRevokeHookInstalled) {
        return;
    }

    gWXRevokeHookAttempts += 1;
    uintptr_t slide = WXFindImageSlide("/Contents/Frameworks/wechat.dylib");
    if (slide == 0) {
        WXAppendLog(@"[hook] attempt=%d failed to find wechat.dylib image slide", gWXRevokeHookAttempts);
        if (gWXRevokeHookAttempts < 40) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                WXInstallRevokeRuntimeHook();
            });
        }
        return;
    }

    uintptr_t entry = slide + kWXRevokeParserEntryVA;
    uintptr_t slot = slide + kWXRevokeParserSlotVA;
    uintptr_t impl = slide + kWXRevokeParserImplVA;
    void **dispatchSlot = (void **)slot;
    if (dispatchSlot == NULL) {
        WXAppendLog(@"[hook] revoke parser slot is null");
        return;
    }

    gWXOriginalRevokeParser = (WXRevokeParserFn)impl;
    *dispatchSlot = (void *)&WXRevokeParserHook;
    gWXRevokeHookInstalled = YES;

    WXAppendLog(@"[hook] installed revoke parser hook entry=0x%lx impl=0x%lx slot=0x%lx current_slot=0x%lx",
                (unsigned long)entry,
                (unsigned long)impl,
                (unsigned long)slot,
                (unsigned long)(uintptr_t)*dispatchSlot);

    dispatch_async(dispatch_get_main_queue(), ^{
        [[WXAssistantController sharedController] updateHookStatus:YES];
    });
}

@implementation WXAssistantController

+ (instancetype)sharedController {
    static WXAssistantController *controller = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        controller = [[WXAssistantController alloc] init];
    });
    return controller;
}

- (void)start {
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(applicationDidFinishLaunching:)
                                                 name:NSApplicationDidFinishLaunchingNotification
                                               object:nil];

    dispatch_async(dispatch_get_main_queue(), ^{
        [self installMenuIfNeeded];
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        WXInstallDeleteRuntimeHook();
        WXInstallRevokeRuntimeHook();
    });
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    [self installMenuIfNeeded];
}

- (void)installMenuIfNeeded {
    NSMenu *mainMenu = [NSApp mainMenu];
    if (mainMenu == nil) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self installMenuIfNeeded];
        });
        return;
    }

    NSMenuItem *existing = [mainMenu itemWithTitle:kWXAssistantMenuTitle];
    if (existing != nil) {
        return;
    }

    NSMenuItem *rootItem = [[NSMenuItem alloc] initWithTitle:kWXAssistantMenuTitle action:nil keyEquivalent:@""];
    NSMenu *submenu = [[NSMenu alloc] initWithTitle:kWXAssistantMenuTitle];

    self.statusMenuItem = [[NSMenuItem alloc] initWithTitle:@"运行时状态：菜单扩展已加载" action:nil keyEquivalent:@""];
    self.statusMenuItem.enabled = NO;
    [submenu addItem:self.statusMenuItem];

    NSMenuItem *modeItem = [[NSMenuItem alloc] initWithTitle:@"防撤回模式：运行时 revoke hook" action:nil keyEquivalent:@""];
    modeItem.enabled = NO;
    [submenu addItem:modeItem];

    self.noticeMenuItem = [[NSMenuItem alloc] initWithTitle:kWXAssistantNoticePending action:nil keyEquivalent:@""];
    self.noticeMenuItem.enabled = NO;
    [submenu addItem:self.noticeMenuItem];

    NSMenuItem *logItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"日志文件：%@", kWXRuntimeLogPath] action:nil keyEquivalent:@""];
    logItem.enabled = NO;
    [submenu addItem:logItem];

    [mainMenu addItem:rootItem];
    [mainMenu setSubmenu:submenu forItem:rootItem];

    [self updateHookStatus:gWXRevokeHookInstalled];
}

- (void)updateHookStatus:(BOOL)installed {
    if (self.statusMenuItem != nil) {
        self.statusMenuItem.title = installed ? @"运行时状态：revoke hook 已加载" : @"运行时状态：等待注入 revokemsg hook";
    }
    if (self.noticeMenuItem != nil) {
        if (!installed) {
            self.noticeMenuItem.title = kWXAssistantNoticePending;
        } else if (gWXDeleteHookInstalled) {
            self.noticeMenuItem.title = @"聊天内撤回提示：原生提示链 + 删除拦截";
        } else {
            self.noticeMenuItem.title = kWXAssistantNoticeReady;
        }
    }
}

@end

__attribute__((constructor))
static void WXRuntimeHookEntry(void) {
    @autoreleasepool {
        [[NSFileManager defaultManager] removeItemAtPath:kWXRuntimeLogPath error:nil];
        WXAppendLog(@"[boot] runtime loader started build=%@", kWXRuntimeBuildTag);
        [[WXAssistantController sharedController] start];
    }
}
