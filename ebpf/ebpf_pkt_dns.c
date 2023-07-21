// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
// eBPF based DNS packets filter to understand
// network access target without gateway
// SKB based DNS packet filter
// attached to 
//   external ports -> optional
//   lo -> mandatory
//   configed ports -> optional
//
// use to identify back to application req/res, not only host level
//

