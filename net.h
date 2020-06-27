/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef NET_H
# define NET_H

int init_rtnetlink_socket();

void net_if_up(int sockfd, const char *name);

#endif /* !NET_H */
