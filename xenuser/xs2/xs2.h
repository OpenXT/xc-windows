/*
 * Copyright (c) 2009 Citrix Systems, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _XS2_H_
#define _XS2_H_

#include <windows.h>

#ifdef XS2API_EXPORTS
#define XS2_API __declspec(dllexport)
#else
#define XS2_API __declspec(dllimport)
#endif


#if defined (__cplusplus)
extern "C" {
#endif

/* An opaque type used to represent handles to the xenstore
 * interface. */
struct xs2_handle;

/* An opaque type used to represent extant watches. */
struct xs2_watch;

/* Open the xenstore interface.  The returned handle should be
 * released with xs2_close() when it is no longer needed.  It is
 * automatically closed when the application exits.
 *
 * Any given handle should only be used from the thread which
 * initially created it.
 *
 * Returns a new xs2_handle on success, or NULL on error.  On error,
 * the error code can be retrieved with GetLastError().
 */
XS2_API struct xs2_handle *WINAPI xs2_open(void);

/* Close a handle to the xenstore interface.  The handle passed in
 * should have been previously returned by xs2_open().  After this
 * function has been called, the handle should not be used by any
 * other functions.
 *
 * If there is an open transaction, it will be aborted.  Any
 * outstanding watches will be cancelled.
 */
XS2_API void WINAPI xs2_close(struct xs2_handle *handle);

/* Start a transaction.  @handle is the xenstore handle (previously
 * returned by xs2_open()) on which to start the transaction.  Only
 * one transaction can be open on any given handle at any time.
 *
 * Returns a hint as to whether the transaction is likely to succeed
 * or fail.  If this function returns FALSE, the transaction is likely
 * to fail.  GetLastError() can be called to give an indication of why
 * the transaction is likely to fail.
 *
 * One of xs2_transaction_commit() and xs2_transaction_abort() must
 * always be called to end the transaction, regardless of the return
 * value of this function.
 *
 * Transactions apply to all data operations (read, write, remove,
 * etc.), but not to non-data operations like watch and unwatch.
 */
XS2_API BOOL WINAPI xs2_transaction_start(struct xs2_handle *handle);
 
/* Abort a transaction.  All operations made in the transaction will
 * be discarded.  There must be a transaction open against the handle
 * when this is called, and the transaction will be closed.
 */
XS2_API void WINAPI xs2_transaction_abort(struct xs2_handle *handle);
 
/* Commit a transaction.  All operations made in the transaction will
 * be made visible to other VMs.  There must be a transaction open
 * against the handle when this is called, and the transaction will be
 * closed (even if there's an error committing it).
 *
 * This can fail due to conflicts with updates made by other VMs.  In
 * that case, this function will return FALSE and GetLastError() will
 * return ERROR_RETRY.  The caller should check that whatever it was
 * trying to do is still valid and retry.
 *
 * Returns FALSE on error and TRUE on success.  On error,
 * GetLastError() can be used to obtain the error code.
 *
 * If any operations in the transaction encountered an error, the
 * transaction will fail to commit, and GetLastError() will report the
 * error which was encountered.
 */
XS2_API BOOL WINAPI xs2_transaction_commit(struct xs2_handle *handle);

/* Write a nul-terminated string @data to the store at location @path.
 * @handle should be an xs2_handle which was previously openned with
 * xs2_open().
 *
 * If a transaction is currently open against the handle, the write
 * operation is bundled into that transaction.
 *
 * Returns TRUE on success, or FALSE on error.  On error, the error
 * code can be retrieved by calling GetLastError().
 */
XS2_API BOOL WINAPI xs2_write(struct xs2_handle *handle, const char *path,
                              const char *data);

/* Write an arbitrary sequence @data of @size bytes to the store at
 * location @path.  @handle should be an xs2_handle which was
 * previously openned with xs2_open().
 *
 * If a transaction is currently open against the handle, the write
 * operation is bundled into that transaction.
 *
 * Returns TRUE on success, or FALSE on error.  On error, the error
 * code can be retrieved by calling GetLastError().
 */
XS2_API BOOL WINAPI xs2_write_bin(struct xs2_handle *handle, const char *path,
                                  const void *data, size_t size);

/* Get the contents of a directory @path in the store, using the xs2
 * handle @handle.
 *
 * @num may be NULL.  If it is not NULL, *@num is set to the number of
 * entries in the directory, or 0 on error.
 *
 * Returns a newly-allocated NULL-terminated array of pointers to
 * newly-allocated nul-terminated strings.  These values can be
 * released with xs2_free().  The entries must be released
 * independently of the main table.  The NULL terminator in the main
 * array is not counted towards the count of directory entries in
 * *@num.
 *
 * If a transaction is currently open against the handle, the
 * directory operation is bundled into that transaction.
 *
 * Returns NULL on error.  In that case, a more specific error code
 * can be retrieved with GetLastError().
 */
XS2_API char **WINAPI xs2_directory(struct xs2_handle *handle,
                                    const char *path,
                                    unsigned int *num);

/* Read the contents of a node @path in the store, using open handle
 * @handle.
 *
 * Returns a newly-allocated buffer containing the contents of the
 * node.  A nul-terminator is automatically added to the end of the
 * returned buffer; this is not included in the size of the value.
 *
 * @len may be NULL.  If it is not NULL, it *@len is set to the size
 * of the returned string, or 0 on error.
 *
 * If a transaction is currently open against the handle, the read
 * operation is bundled into that transaction.
 *
 * Returns NULL on error.  GetLastError() will return the error code.
 */
XS2_API void * WINAPI xs2_read(HANDLE hXS, const char *path, size_t *len);

/* Remove the node @path from the store, using open handle @handle.
 *
 * If a transaction is currently open against the handle, the remove
 * operation is bundled into that transaction.
 *
 * Returns TRUE on success, or FALSE on error.  On error,
 * GetLastError() will return the error code.
 */
XS2_API BOOL WINAPI xs2_remove(HANDLE hXS, const char *path);

/* Create a watch on a xenstore node @path using open handle @handle.
 * The event @event will be notified shortly after the contents of the
 * node changes.  There are no other guarantees on the behaviour of
 * this function.  In particular:
 *
 * -- The event may be notified when the path hasn't actually changed
 * -- The event may be notified several times for a single change
 * -- The event may only be notified once if the node changes several
 *    times in rapid succession.
 *
 * The returned watch handler should be released with xs2_unwatch()
 * when it is no longer needed.
 *
 * Returns a new watch structure on success, or NULL on error.  On
 * error, GetLastError() will return the error code.
 *
 * If the handle is closed before the watch is released, the watch
 * will no longer function, but it must still be released with
 * xs2_unwatch().
 */
XS2_API struct xs2_watch * WINAPI xs2_watch(struct xs2_handle *handle,
                                            const char *path,
                                            HANDLE event);

/* Release the watch @watch which was previously created with
 * xs2_watch().  This always succeeds (provided @watch is valid).
 */
XS2_API void WINAPI xs2_unwatch(struct xs2_watch *watch);

/* Release memory allocated by the xs2 library.  The semantics are
 * similar to the C standard library free() function: the memory at
 * @mem must have been previously allocated, and not already freed,
 * and once xs2_free() has been called any access to @mem is invalid.
 */
XS2_API VOID WINAPI xs2_free(const void *mem);

#if defined (__cplusplus)
};
#endif

#endif // _XS2_H_
