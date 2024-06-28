/* Copyright © 2021-2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef FD_H_
# define FD_H_

int recv_fd(int socket);
void send_fd(int socket, int fd);
void rebind_fds_and_close_rest(int start_fd, ...);
void close_null(int fd);

#endif /* !FD_H */
